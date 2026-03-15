package storage

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"github.com/shuklarituparn/Gopherpass/internal/models"
)


type SecretRepo struct {
	*BaseRepository[models.Secret, string]
}

func NewSecretRepo(db *sql.DB) *SecretRepo {
	return &SecretRepo{
		BaseRepository: NewBaseRepository[models.Secret, string](db, "secrets"),
	}
}

func secretRowScanner() RowScanner[models.Secret] {
	return func(row *sql.Row) (*models.Secret, error) {
		secret := &models.Secret{}
		err := row.Scan(
			&secret.ID, &secret.UserID, &secret.Name, &secret.DataType,
			&secret.EncryptedData, &secret.Metadata, &secret.Version,
			&secret.CreatedAt, &secret.UpdatedAt, &secret.DeletedAt,
		)
		if err != nil {
			if IsNotFound(err) {
				return nil, ErrSecretNotFound
			}
			return nil, err
		}
		return secret, nil
	}
}

func secretRowsScanner() RowsScanner[models.Secret] {
	return func(rows *sql.Rows) (*models.Secret, error) {
		secret := &models.Secret{}
		err := rows.Scan(
			&secret.ID, &secret.UserID, &secret.Name, &secret.DataType,
			&secret.EncryptedData, &secret.Metadata, &secret.Version,
			&secret.CreatedAt, &secret.UpdatedAt, &secret.DeletedAt,
		)
		if err != nil {
			return nil, err
		}
		return secret, nil
	}
}

func (r *SecretRepo) Create(ctx context.Context, secret *models.Secret) error {
	if secret.ID == "" {
		secret.ID = uuid.New().String()
	}

	now := time.Now()
	secret.SetCreatedAt(now)
	secret.SetUpdatedAt(now)
	secret.Version = 1

	query := `
		INSERT INTO secrets (id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := r.ExecContext(ctx, query,
		secret.ID, secret.UserID, secret.Name, secret.DataType,
		secret.EncryptedData, secret.Metadata, secret.Version,
		secret.CreatedAt, secret.UpdatedAt,
	)

	return err
}

func (r *SecretRepo) GetByID(ctx context.Context, id string) (*models.Secret, error) {
	query := `
		SELECT id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at, deleted_at
		FROM secrets
		WHERE id = $1`

	return ScanOne(ctx, r.DB(), secretRowScanner(), query, id)
}

func (r *SecretRepo) GetByIDForUser(ctx context.Context, userID int64, secretID string) (*models.Secret, error) {
	query := `
		SELECT id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at, deleted_at
		FROM secrets
		WHERE id = $1 AND user_id = $2`

	return ScanOne(ctx, r.DB(), secretRowScanner(), query, secretID, userID)
}

func (r *SecretRepo) List(ctx context.Context) ([]models.Secret, error) {
	query := `
		SELECT id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at, deleted_at
		FROM secrets
		WHERE deleted_at IS NULL
		ORDER BY updated_at DESC`

	return ScanMany(ctx, r.DB(), secretRowsScanner(), query)
}

func (r *SecretRepo) ListByUser(ctx context.Context, userID int64) ([]models.Secret, error) {
	query := `
		SELECT id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at, deleted_at
		FROM secrets
		WHERE user_id = $1 AND deleted_at IS NULL
		ORDER BY updated_at DESC`

	return ScanMany(ctx, r.DB(), secretRowsScanner(), query, userID)
}

func (r *SecretRepo) ListModifiedSince(ctx context.Context, userID int64, since time.Time) ([]models.Secret, error) {
	query := `
		SELECT id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at, deleted_at
		FROM secrets
		WHERE user_id = $1 AND updated_at > $2
		ORDER BY updated_at ASC`

	return ScanMany(ctx, r.DB(), secretRowsScanner(), query, userID, since)
}

func (r *SecretRepo) ListDeletedSince(ctx context.Context, userID int64, since time.Time) ([]string, error) {
	query := `
		SELECT id
		FROM secrets
		WHERE user_id = $1 AND deleted_at IS NOT NULL AND deleted_at > $2`

	rows, err := r.QueryContext(ctx, query, userID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}

	return ids, rows.Err()
}

func (r *SecretRepo) Update(ctx context.Context, secret *models.Secret) error {
	query := `
		UPDATE secrets
		SET name = $1, encrypted_data = $2, metadata = $3, version = version + 1, updated_at = $4
		WHERE id = $5 AND user_id = $6 AND version = $7 AND deleted_at IS NULL
		RETURNING version`

	secret.SetUpdatedAt(time.Now())

	var newVersion int64
	err := r.QueryRowContext(ctx, query,
		secret.Name, secret.EncryptedData, secret.Metadata, secret.UpdatedAt,
		secret.ID, secret.UserID, secret.Version,
	).Scan(&newVersion)

	if err != nil {
		if IsNotFound(err) {
			// Check if secret exists but version mismatched
			existing, checkErr := r.GetByIDForUser(ctx, secret.UserID, secret.ID)
			if checkErr != nil {
				return ErrSecretNotFound
			}
			if existing.Version != secret.Version {
				return ErrVersionConflict
			}
			return ErrSecretNotFound
		}
		return err
	}

	secret.Version = newVersion
	return nil
}

func (r *SecretRepo) Delete(ctx context.Context, id string) error {
	query := `
		UPDATE secrets
		SET deleted_at = $1, updated_at = $1
		WHERE id = $2 AND deleted_at IS NULL`

	result, err := r.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrSecretNotFound
	}

	return nil
}

func (r *SecretRepo) DeleteForUser(ctx context.Context, userID int64, secretID string) error {
	query := `
		UPDATE secrets
		SET deleted_at = $1, updated_at = $1
		WHERE id = $2 AND user_id = $3 AND deleted_at IS NULL`

	result, err := r.ExecContext(ctx, query, time.Now(), secretID, userID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrSecretNotFound
	}

	return nil
}

func (r *SecretRepo) HardDelete(ctx context.Context, id string) error {
	query := `DELETE FROM secrets WHERE id = $1`

	result, err := r.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrSecretNotFound
	}

	return nil
}