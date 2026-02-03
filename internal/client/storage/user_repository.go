package storage

import (
	"context"
	"database/sql"
	"time"

	"github.com/shuklarituparn/Gopherpass/internal/models"
)


type UserRepo struct {
	*BaseRepository[models.User, int64]
}

func NewUserRepo(db *sql.DB) *UserRepo {
	return &UserRepo{
		BaseRepository: NewBaseRepository[models.User, int64](db, "users"),
	}
}

func userRowScanner() RowScanner[models.User] {
	return func(row *sql.Row) (*models.User, error) {
		user := &models.User{}
		err := row.Scan(
			&user.ID, &user.Login, &user.PasswordHash,
			&user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			if IsNotFound(err) {
				return nil, ErrUserNotFound
			}
			return nil, err
		}
		return user, nil
	}
}

func userRowsScanner() RowsScanner[models.User] {
	return func(rows *sql.Rows) (*models.User, error) {
		user := &models.User{}
		err := rows.Scan(
			&user.ID, &user.Login, &user.PasswordHash,
			&user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		return user, nil
	}
}

func (r *UserRepo) Create(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (login, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id`

	now := time.Now()
	user.SetCreatedAt(now)
	user.SetUpdatedAt(now)

	err := r.QueryRowContext(ctx, query,
		user.Login, user.PasswordHash, user.CreatedAt, user.UpdatedAt,
	).Scan(&user.ID)

	if err != nil {
		if isUniqueViolation(err) {
			return ErrUserExists
		}
		return err
	}

	return nil
}

func (r *UserRepo) GetByID(ctx context.Context, id int64) (*models.User, error) {
	query := `
		SELECT id, login, password_hash, created_at, updated_at
		FROM users
		WHERE id = $1`

	return ScanOne(ctx, r.DB(), userRowScanner(), query, id)
}

func (r *UserRepo) GetByLogin(ctx context.Context, login string) (*models.User, error) {
	query := `
		SELECT id, login, password_hash, created_at, updated_at
		FROM users
		WHERE login = $1`

	return ScanOne(ctx, r.DB(), userRowScanner(), query, login)
}

func (r *UserRepo) List(ctx context.Context) ([]models.User, error) {
	query := `
		SELECT id, login, password_hash, created_at, updated_at
		FROM users
		ORDER BY id`

	return ScanMany(ctx, r.DB(), userRowsScanner(), query)
}

func (r *UserRepo) Update(ctx context.Context, user *models.User) error {
	query := `
		UPDATE users
		SET login = $1, password_hash = $2, updated_at = $3
		WHERE id = $4`

	user.SetUpdatedAt(time.Now())

	result, err := r.ExecContext(ctx, query,
		user.Login, user.PasswordHash, user.UpdatedAt, user.ID,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (r *UserRepo) Delete(ctx context.Context, id int64) error {
	query := `DELETE FROM users WHERE id = $1`

	result, err := r.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}