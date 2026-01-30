package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/shuklarituparn/Gopherpass/internal/models"
)

var (
	ErrUserNotFound     = errors.New("user not found")
	ErrUserExists       = errors.New("user already exists")
	ErrSecretNotFound   = errors.New("secret not found")
	ErrVersionConflict  = errors.New("version conflict")
	ErrDatabaseError    = errors.New("database error")
)

type Storage interface {
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByLogin(ctx context.Context, login string) (*models.User, error)
	GetUserByID(ctx context.Context, id int64) (*models.User, error)

	CreateSecret(ctx context.Context, secret *models.Secret) error
	GetSecret(ctx context.Context, userID int64, secretID string) (*models.Secret, error)
	GetSecretsByUser(ctx context.Context, userID int64) ([]models.Secret, error)
	GetSecretsModifiedSince(ctx context.Context, userID int64, since time.Time) ([]models.Secret, error)
	UpdateSecret(ctx context.Context, secret *models.Secret) error
	DeleteSecret(ctx context.Context, userID int64, secretID string) error

	GetDeletedSecrets(ctx context.Context, userID int64, since time.Time) ([]string, error)

	Ping(ctx context.Context) error
	Close() error
}

type PostgresStorage struct {
	db *sql.DB
}

func NewPostgresStorage(dsn string) (*PostgresStorage, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, err
	}

	storage := &PostgresStorage{db: db}
	if err := storage.migrate(); err != nil {
		return nil, err
	}

	return storage, nil
}

func (s *PostgresStorage) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id BIGSERIAL PRIMARY KEY,
			login VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS secrets (
			id VARCHAR(36) PRIMARY KEY,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			name VARCHAR(255) NOT NULL,
			data_type INTEGER NOT NULL,
			encrypted_data BYTEA NOT NULL,
			metadata TEXT DEFAULT '',
			version BIGINT DEFAULT 1,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			deleted_at TIMESTAMP WITH TIME ZONE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_secrets_user_id ON secrets(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_secrets_updated_at ON secrets(updated_at)`,
		`CREATE INDEX IF NOT EXISTS idx_secrets_user_updated ON secrets(user_id, updated_at)`,
	}

	for _, migration := range migrations {
		if _, err := s.db.Exec(migration); err != nil {
			return err
		}
	}

	return nil
}

func (s *PostgresStorage) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *PostgresStorage) Close() error {
	return s.db.Close()
}

func (s *PostgresStorage) CreateUser(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (login, password_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id`

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	err := s.db.QueryRowContext(ctx, query,
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

func (s *PostgresStorage) GetUserByLogin(ctx context.Context, login string) (*models.User, error) {
	query := `
		SELECT id, login, password_hash, created_at, updated_at
		FROM users
		WHERE login = $1`

	user := &models.User{}
	err := s.db.QueryRowContext(ctx, query, login).Scan(
		&user.ID, &user.Login, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}

func (s *PostgresStorage) GetUserByID(ctx context.Context, id int64) (*models.User, error) {
	query := `
		SELECT id, login, password_hash, created_at, updated_at
		FROM users
		WHERE id = $1`

	user := &models.User{}
	err := s.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.Login, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}

func (s *PostgresStorage) CreateSecret(ctx context.Context, secret *models.Secret) error {
	if secret.ID == "" {
		secret.ID = uuid.New().String()
	}

	now := time.Now()
	secret.CreatedAt = now
	secret.UpdatedAt = now
	secret.Version = 1

	query := `
		INSERT INTO secrets (id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := s.db.ExecContext(ctx, query,
		secret.ID, secret.UserID, secret.Name, secret.DataType,
		secret.EncryptedData, secret.Metadata, secret.Version,
		secret.CreatedAt, secret.UpdatedAt,
	)

	return err
}

func (s *PostgresStorage) GetSecret(ctx context.Context, userID int64, secretID string) (*models.Secret, error) {
	query := `
		SELECT id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at, deleted_at
		FROM secrets
		WHERE id = $1 AND user_id = $2`

	secret := &models.Secret{}
	err := s.db.QueryRowContext(ctx, query, secretID, userID).Scan(
		&secret.ID, &secret.UserID, &secret.Name, &secret.DataType,
		&secret.EncryptedData, &secret.Metadata, &secret.Version,
		&secret.CreatedAt, &secret.UpdatedAt, &secret.DeletedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSecretNotFound
		}
		return nil, err
	}

	return secret, nil
}

func (s *PostgresStorage) GetSecretsByUser(ctx context.Context, userID int64) ([]models.Secret, error) {
	query := `
		SELECT id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at, deleted_at
		FROM secrets
		WHERE user_id = $1 AND deleted_at IS NULL
		ORDER BY updated_at DESC`

	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var secrets []models.Secret
	for rows.Next() {
		var secret models.Secret
		if err := rows.Scan(
			&secret.ID, &secret.UserID, &secret.Name, &secret.DataType,
			&secret.EncryptedData, &secret.Metadata, &secret.Version,
			&secret.CreatedAt, &secret.UpdatedAt, &secret.DeletedAt,
		); err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return secrets, nil
}

func (s *PostgresStorage) GetSecretsModifiedSince(ctx context.Context, userID int64, since time.Time) ([]models.Secret, error) {
	query := `
		SELECT id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at, deleted_at
		FROM secrets
		WHERE user_id = $1 AND updated_at > $2
		ORDER BY updated_at ASC`

	rows, err := s.db.QueryContext(ctx, query, userID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var secrets []models.Secret
	for rows.Next() {
		var secret models.Secret
		if err := rows.Scan(
			&secret.ID, &secret.UserID, &secret.Name, &secret.DataType,
			&secret.EncryptedData, &secret.Metadata, &secret.Version,
			&secret.CreatedAt, &secret.UpdatedAt, &secret.DeletedAt,
		); err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return secrets, nil
}

func (s *PostgresStorage) UpdateSecret(ctx context.Context, secret *models.Secret) error {
	query := `
		UPDATE secrets
		SET name = $1, encrypted_data = $2, metadata = $3, version = version + 1, updated_at = $4
		WHERE id = $5 AND user_id = $6 AND version = $7 AND deleted_at IS NULL
		RETURNING version`

	secret.UpdatedAt = time.Now()

	var newVersion int64
	err := s.db.QueryRowContext(ctx, query,
		secret.Name, secret.EncryptedData, secret.Metadata, secret.UpdatedAt,
		secret.ID, secret.UserID, secret.Version,
	).Scan(&newVersion)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			existing, checkErr := s.GetSecret(ctx, secret.UserID, secret.ID)
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

func (s *PostgresStorage) DeleteSecret(ctx context.Context, userID int64, secretID string) error {
	query := `
		UPDATE secrets
		SET deleted_at = $1, updated_at = $1
		WHERE id = $2 AND user_id = $3 AND deleted_at IS NULL`

	result, err := s.db.ExecContext(ctx, query, time.Now(), secretID, userID)
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

func (s *PostgresStorage) GetDeletedSecrets(ctx context.Context, userID int64, since time.Time) ([]string, error) {
	query := `
		SELECT id
		FROM secrets
		WHERE user_id = $1 AND deleted_at IS NOT NULL AND deleted_at > $2`

	rows, err := s.db.QueryContext(ctx, query, userID, since)
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

func isUniqueViolation(err error) bool {
	return err != nil && (
		containsString(err.Error(), "23505") ||
			containsString(err.Error(), "unique constraint") ||
			containsString(err.Error(), "duplicate key"))
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
