package storage

import (
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/shuklarituparn/Gopherpass/internal/models"
)

var (
	ErrSecretNotFound = errors.New("secret not found")
	ErrDatabaseError  = errors.New("database error")
)

type LocalStorage struct {
	db *sql.DB
}

func NewLocalStorage(dbPath string) (*LocalStorage, error) {
	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on")
	if err != nil {
		return nil, err
	}

	storage := &LocalStorage{db: db}
	if err := storage.migrate(); err != nil {
		db.Close()
		return nil, err
	}

	return storage, nil
}

func (s *LocalStorage) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS secrets (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			data_type INTEGER NOT NULL,
			encrypted_data BLOB NOT NULL,
			metadata TEXT DEFAULT '',
			version INTEGER DEFAULT 1,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			deleted_at DATETIME,
			synced INTEGER DEFAULT 0,
			local_modified INTEGER DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_secrets_synced ON secrets(synced)`,
		`CREATE INDEX IF NOT EXISTS idx_secrets_modified ON secrets(local_modified)`,
		`CREATE TABLE IF NOT EXISTS sync_state (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			last_sync_time DATETIME,
			user_id INTEGER
		)`,
		`INSERT OR IGNORE INTO sync_state (id, last_sync_time) VALUES (1, NULL)`,
	}

	for _, migration := range migrations {
		if _, err := s.db.Exec(migration); err != nil {
			return err
		}
	}

	return nil
}

func (s *LocalStorage) Close() error {
	return s.db.Close()
}

func (s *LocalStorage) CreateSecret(secret *models.Secret) error {
	if secret.ID == "" {
		secret.ID = uuid.New().String()
	}

	now := time.Now()
	secret.CreatedAt = now
	secret.UpdatedAt = now
	secret.Version = 1

	query := `
		INSERT INTO secrets (id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at, synced, local_modified)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1)`

	_, err := s.db.Exec(query,
		secret.ID, secret.UserID, secret.Name, secret.DataType,
		secret.EncryptedData, secret.Metadata, secret.Version,
		secret.CreatedAt, secret.UpdatedAt,
	)

	return err
}

func (s *LocalStorage) GetSecret(id string) (*models.Secret, error) {
	query := `
		SELECT id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at, deleted_at
		FROM secrets
		WHERE id = ? AND deleted_at IS NULL`

	secret := &models.Secret{}
	err := s.db.QueryRow(query, id).Scan(
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

func (s *LocalStorage) GetAllSecrets() ([]models.Secret, error) {
	query := `
		SELECT id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at, deleted_at
		FROM secrets
		WHERE deleted_at IS NULL
		ORDER BY updated_at DESC`

	rows, err := s.db.Query(query)
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

	return secrets, rows.Err()
}

func (s *LocalStorage) GetSecretsByType(dataType models.DataType) ([]models.Secret, error) {
	query := `
		SELECT id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at, deleted_at
		FROM secrets
		WHERE data_type = ? AND deleted_at IS NULL
		ORDER BY updated_at DESC`

	rows, err := s.db.Query(query, dataType)
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

	return secrets, rows.Err()
}

func (s *LocalStorage) UpdateSecret(secret *models.Secret) error {
	secret.UpdatedAt = time.Now()

	query := `
		UPDATE secrets
		SET name = ?, encrypted_data = ?, metadata = ?, version = version + 1, updated_at = ?, local_modified = 1
		WHERE id = ? AND deleted_at IS NULL`

	result, err := s.db.Exec(query,
		secret.Name, secret.EncryptedData, secret.Metadata, secret.UpdatedAt, secret.ID,
	)
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

func (s *LocalStorage) DeleteSecret(id string) error {
	query := `
		UPDATE secrets
		SET deleted_at = ?, updated_at = ?, local_modified = 1
		WHERE id = ? AND deleted_at IS NULL`

	now := time.Now()
	result, err := s.db.Exec(query, now, now, id)
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

func (s *LocalStorage) GetLocallyModifiedSecrets() ([]models.Secret, error) {
	query := `
		SELECT id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at, deleted_at
		FROM secrets
		WHERE local_modified = 1`

	rows, err := s.db.Query(query)
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

	return secrets, rows.Err()
}

func (s *LocalStorage) MarkAsSynced(id string) error {
	query := `UPDATE secrets SET synced = 1, local_modified = 0 WHERE id = ?`
	_, err := s.db.Exec(query, id)
	return err
}

func (s *LocalStorage) UpsertSecret(secret *models.Secret) error {
	query := `
		INSERT INTO secrets (id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at, deleted_at, synced, local_modified)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			encrypted_data = excluded.encrypted_data,
			metadata = excluded.metadata,
			version = excluded.version,
			updated_at = excluded.updated_at,
			deleted_at = excluded.deleted_at,
			synced = 1,
			local_modified = 0`

	_, err := s.db.Exec(query,
		secret.ID, secret.UserID, secret.Name, secret.DataType,
		secret.EncryptedData, secret.Metadata, secret.Version,
		secret.CreatedAt, secret.UpdatedAt, secret.DeletedAt,
	)

	return err
}

func (s *LocalStorage) DeleteSecretPermanently(id string) error {
	query := `DELETE FROM secrets WHERE id = ?`
	_, err := s.db.Exec(query, id)
	return err
}

func (s *LocalStorage) GetLastSyncTime() (time.Time, error) {
	var lastSyncTime sql.NullTime
	query := `SELECT last_sync_time FROM sync_state WHERE id = 1`
	err := s.db.QueryRow(query).Scan(&lastSyncTime)
	if err != nil {
		return time.Time{}, err
	}
	if !lastSyncTime.Valid {
		return time.Time{}, nil
	}
	return lastSyncTime.Time, nil
}

func (s *LocalStorage) SetLastSyncTime(t time.Time) error {
	query := `UPDATE sync_state SET last_sync_time = ? WHERE id = 1`
	_, err := s.db.Exec(query, t)
	return err
}

func (s *LocalStorage) ClearAll() error {
	queries := []string{
		`DELETE FROM secrets`,
		`UPDATE sync_state SET last_sync_time = NULL, user_id = NULL`,
	}
	for _, query := range queries {
		if _, err := s.db.Exec(query); err != nil {
			return err
		}
	}
	return nil
}

func (s *LocalStorage) SearchSecrets(query string) ([]models.Secret, error) {
	sqlQuery := `
		SELECT id, user_id, name, data_type, encrypted_data, metadata, version, created_at, updated_at, deleted_at
		FROM secrets
		WHERE name LIKE ? AND deleted_at IS NULL
		ORDER BY updated_at DESC`

	rows, err := s.db.Query(sqlQuery, "%"+query+"%")
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

	return secrets, rows.Err()
}
