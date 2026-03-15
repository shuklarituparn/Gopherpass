package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	_ "github.com/lib/pq" 

	"github.com/shuklarituparn/Gopherpass/internal/models"
)

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrUserExists      = errors.New("user already exists")
	ErrSecretNotFound  = errors.New("secret not found")
	ErrVersionConflict = errors.New("version conflict")
	ErrDatabaseError   = errors.New("database error")
)

type UserRepository interface {
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByLogin(ctx context.Context, login string) (*models.User, error)
	GetUserByID(ctx context.Context, id int64) (*models.User, error)
}

type SecretRepository interface {
	CreateSecret(ctx context.Context, secret *models.Secret) error
	GetSecret(ctx context.Context, userID int64, secretID string) (*models.Secret, error)
	GetSecretsByUser(ctx context.Context, userID int64) ([]models.Secret, error)
	UpdateSecret(ctx context.Context, secret *models.Secret) error
	DeleteSecret(ctx context.Context, userID int64, secretID string) error
}

type SyncRepository interface {
	GetSecretsModifiedSince(ctx context.Context, userID int64, since time.Time) ([]models.Secret, error)
	GetDeletedSecrets(ctx context.Context, userID int64, since time.Time) ([]string, error)
}

type HealthChecker interface {
	Ping(ctx context.Context) error
	Close() error
}


type Storage interface {
	UserRepository
	SecretRepository
	SyncRepository
	HealthChecker
}


type PostgresStorage struct {
	db         *sql.DB
	userRepo   *UserRepo
	secretRepo *SecretRepo
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

	storage := &PostgresStorage{
		db:         db,
		userRepo:   NewUserRepo(db),
		secretRepo: NewSecretRepo(db),
	}

	if err := storage.migrate(); err != nil {
		return nil, err
	}

	return storage, nil
}

func (s *PostgresStorage) UserRepository() *UserRepo {
	return s.userRepo
}

func (s *PostgresStorage) SecretRepoGeneric() *SecretRepo {
	return s.secretRepo
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
	return s.userRepo.Create(ctx, user)
}


func (s *PostgresStorage) GetUserByLogin(ctx context.Context, login string) (*models.User, error) {
	return s.userRepo.GetByLogin(ctx, login)
}


func (s *PostgresStorage) GetUserByID(ctx context.Context, id int64) (*models.User, error) {
	return s.userRepo.GetByID(ctx, id)
}


func (s *PostgresStorage) CreateSecret(ctx context.Context, secret *models.Secret) error {
	return s.secretRepo.Create(ctx, secret)
}


func (s *PostgresStorage) GetSecret(ctx context.Context, userID int64, secretID string) (*models.Secret, error) {
	return s.secretRepo.GetByIDForUser(ctx, userID, secretID)
}


func (s *PostgresStorage) GetSecretsByUser(ctx context.Context, userID int64) ([]models.Secret, error) {
	return s.secretRepo.ListByUser(ctx, userID)
}


func (s *PostgresStorage) GetSecretsModifiedSince(ctx context.Context, userID int64, since time.Time) ([]models.Secret, error) {
	return s.secretRepo.ListModifiedSince(ctx, userID, since)
}


func (s *PostgresStorage) UpdateSecret(ctx context.Context, secret *models.Secret) error {
	return s.secretRepo.Update(ctx, secret)
}


func (s *PostgresStorage) DeleteSecret(ctx context.Context, userID int64, secretID string) error {
	return s.secretRepo.DeleteForUser(ctx, userID, secretID)
}


func (s *PostgresStorage) GetDeletedSecrets(ctx context.Context, userID int64, since time.Time) ([]string, error) {
	return s.secretRepo.ListDeletedSince(ctx, userID, since)
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