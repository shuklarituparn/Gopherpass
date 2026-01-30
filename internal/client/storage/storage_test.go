package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shuklarituparn/Gopherpass/internal/models"
)

func setupTestDB(t *testing.T) (*LocalStorage, func()) {
	tmpDir, err := os.MkdirTemp("", "gophkeeper-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	storage, err := NewLocalStorage(dbPath)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create storage: %v", err)
	}

	cleanup := func() {
		storage.Close()
		os.RemoveAll(tmpDir)
	}

	return storage, cleanup
}

func TestNewLocalStorage(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	if storage == nil {
		t.Error("NewLocalStorage() returned nil")
	}
}

func TestNewLocalStorage_InvalidPath(t *testing.T) {
	_, err := NewLocalStorage("/nonexistent/path/that/cannot/exist/test.db")
	if err == nil {
		t.Error("NewLocalStorage() should fail for invalid path")
	}
}

func TestLocalStorage_CreateSecret(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	secret := &models.Secret{
		UserID:        1,
		Name:          "Test Secret",
		DataType:      models.DataTypeLoginPassword,
		EncryptedData: []byte("encrypted data"),
		Metadata:      "test metadata",
	}

	err := storage.CreateSecret(secret)
	if err != nil {
		t.Errorf("CreateSecret() error = %v", err)
	}

	if secret.ID == "" {
		t.Error("CreateSecret() did not set ID")
	}

	if secret.Version != 1 {
		t.Errorf("CreateSecret() Version = %v, want 1", secret.Version)
	}
}

func TestLocalStorage_GetSecret(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	secret := &models.Secret{
		UserID:        1,
		Name:          "Test Secret",
		DataType:      models.DataTypeText,
		EncryptedData: []byte("encrypted"),
		Metadata:      "meta",
	}
	storage.CreateSecret(secret)

	retrieved, err := storage.GetSecret(secret.ID)
	if err != nil {
		t.Errorf("GetSecret() error = %v", err)
	}

	if retrieved.Name != "Test Secret" {
		t.Errorf("GetSecret() Name = %v, want 'Test Secret'", retrieved.Name)
	}

	if retrieved.DataType != models.DataTypeText {
		t.Errorf("GetSecret() DataType = %v, want DataTypeText", retrieved.DataType)
	}
}

func TestLocalStorage_GetSecret_NotFound(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	_, err := storage.GetSecret("nonexistent-id")
	if err != ErrSecretNotFound {
		t.Errorf("GetSecret() error = %v, want ErrSecretNotFound", err)
	}
}

func TestLocalStorage_GetAllSecrets(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	for i := 0; i < 3; i++ {
		secret := &models.Secret{
			UserID:        1,
			Name:          "Secret",
			DataType:      models.DataTypeText,
			EncryptedData: []byte("data"),
		}
		storage.CreateSecret(secret)
	}

	secrets, err := storage.GetAllSecrets()
	if err != nil {
		t.Errorf("GetAllSecrets() error = %v", err)
	}

	if len(secrets) != 3 {
		t.Errorf("GetAllSecrets() returned %d secrets, want 3", len(secrets))
	}
}

func TestLocalStorage_GetSecretsByType(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	types := []models.DataType{
		models.DataTypeLoginPassword,
		models.DataTypeLoginPassword,
		models.DataTypeText,
		models.DataTypeCard,
	}

	for _, dt := range types {
		secret := &models.Secret{
			UserID:        1,
			Name:          "Secret",
			DataType:      dt,
			EncryptedData: []byte("data"),
		}
		storage.CreateSecret(secret)
	}

	secrets, err := storage.GetSecretsByType(models.DataTypeLoginPassword)
	if err != nil {
		t.Errorf("GetSecretsByType() error = %v", err)
	}

	if len(secrets) != 2 {
		t.Errorf("GetSecretsByType() returned %d secrets, want 2", len(secrets))
	}
}

func TestLocalStorage_UpdateSecret(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	secret := &models.Secret{
		UserID:        1,
		Name:          "Original Name",
		DataType:      models.DataTypeText,
		EncryptedData: []byte("original data"),
	}
	storage.CreateSecret(secret)

	secret.Name = "Updated Name"
	secret.EncryptedData = []byte("updated data")
	err := storage.UpdateSecret(secret)
	if err != nil {
		t.Errorf("UpdateSecret() error = %v", err)
	}

	retrieved, _ := storage.GetSecret(secret.ID)
	if retrieved.Name != "Updated Name" {
		t.Errorf("UpdateSecret() Name = %v, want 'Updated Name'", retrieved.Name)
	}
}

func TestLocalStorage_UpdateSecret_NotFound(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	secret := &models.Secret{
		ID:            "nonexistent",
		Name:          "Test",
		EncryptedData: []byte("data"),
	}

	err := storage.UpdateSecret(secret)
	if err != ErrSecretNotFound {
		t.Errorf("UpdateSecret() error = %v, want ErrSecretNotFound", err)
	}
}

func TestLocalStorage_DeleteSecret(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	secret := &models.Secret{
		UserID:        1,
		Name:          "To Delete",
		DataType:      models.DataTypeText,
		EncryptedData: []byte("data"),
	}
	storage.CreateSecret(secret)

	err := storage.DeleteSecret(secret.ID)
	if err != nil {
		t.Errorf("DeleteSecret() error = %v", err)
	}

	_, err = storage.GetSecret(secret.ID)
	if err != ErrSecretNotFound {
		t.Error("GetSecret() should return ErrSecretNotFound after deletion")
	}
}

func TestLocalStorage_DeleteSecret_NotFound(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	err := storage.DeleteSecret("nonexistent-id")
	if err != ErrSecretNotFound {
		t.Errorf("DeleteSecret() error = %v, want ErrSecretNotFound", err)
	}
}

func TestLocalStorage_GetLocallyModifiedSecrets(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	secret := &models.Secret{
		UserID:        1,
		Name:          "Modified Secret",
		DataType:      models.DataTypeText,
		EncryptedData: []byte("data"),
	}
	storage.CreateSecret(secret)

	modified, err := storage.GetLocallyModifiedSecrets()
	if err != nil {
		t.Errorf("GetLocallyModifiedSecrets() error = %v", err)
	}

	if len(modified) != 1 {
		t.Errorf("GetLocallyModifiedSecrets() returned %d secrets, want 1", len(modified))
	}
}

func TestLocalStorage_MarkAsSynced(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	secret := &models.Secret{
		UserID:        1,
		Name:          "Test",
		DataType:      models.DataTypeText,
		EncryptedData: []byte("data"),
	}
	storage.CreateSecret(secret)

	err := storage.MarkAsSynced(secret.ID)
	if err != nil {
		t.Errorf("MarkAsSynced() error = %v", err)
	}

	modified, _ := storage.GetLocallyModifiedSecrets()
	if len(modified) != 0 {
		t.Error("MarkAsSynced() did not clear local_modified flag")
	}
}

func TestLocalStorage_UpsertSecret(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	now := time.Now()
	secret := &models.Secret{
		ID:            "upsert-test",
		UserID:        1,
		Name:          "Upsert Test",
		DataType:      models.DataTypeText,
		EncryptedData: []byte("data"),
		Version:       1,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	err := storage.UpsertSecret(secret)
	if err != nil {
		t.Errorf("UpsertSecret() insert error = %v", err)
	}

	secret.Name = "Updated via Upsert"
	secret.Version = 2
	err = storage.UpsertSecret(secret)
	if err != nil {
		t.Errorf("UpsertSecret() update error = %v", err)
	}

	retrieved, _ := storage.GetSecret("upsert-test")
	if retrieved.Name != "Updated via Upsert" {
		t.Errorf("UpsertSecret() Name = %v", retrieved.Name)
	}
}

func TestLocalStorage_DeleteSecretPermanently(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	secret := &models.Secret{
		UserID:        1,
		Name:          "Permanent Delete",
		DataType:      models.DataTypeText,
		EncryptedData: []byte("data"),
	}
	storage.CreateSecret(secret)

	err := storage.DeleteSecretPermanently(secret.ID)
	if err != nil {
		t.Errorf("DeleteSecretPermanently() error = %v", err)
	}
}

func TestLocalStorage_SyncTime(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	syncTime, err := storage.GetLastSyncTime()
	if err != nil {
		t.Errorf("GetLastSyncTime() error = %v", err)
	}
	if !syncTime.IsZero() {
		t.Error("Initial GetLastSyncTime() should be zero")
	}

	now := time.Now().Truncate(time.Second)
	err = storage.SetLastSyncTime(now)
	if err != nil {
		t.Errorf("SetLastSyncTime() error = %v", err)
	}

	syncTime, _ = storage.GetLastSyncTime()
	if !syncTime.Equal(now) {
		t.Errorf("GetLastSyncTime() = %v, want %v", syncTime, now)
	}
}

func TestLocalStorage_ClearAll(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	secret := &models.Secret{
		UserID:        1,
		Name:          "Test",
		DataType:      models.DataTypeText,
		EncryptedData: []byte("data"),
	}
	storage.CreateSecret(secret)
	storage.SetLastSyncTime(time.Now())

	err := storage.ClearAll()
	if err != nil {
		t.Errorf("ClearAll() error = %v", err)
	}

	secrets, _ := storage.GetAllSecrets()
	if len(secrets) != 0 {
		t.Error("ClearAll() did not remove secrets")
	}

	syncTime, _ := storage.GetLastSyncTime()
	if !syncTime.IsZero() {
		t.Error("ClearAll() did not reset sync time")
	}
}

func TestLocalStorage_SearchSecrets(t *testing.T) {
	storage, cleanup := setupTestDB(t)
	defer cleanup()

	secrets := []string{"GitHub Password", "Gmail Login", "Bank Account"}
	for _, name := range secrets {
		s := &models.Secret{
			UserID:        1,
			Name:          name,
			DataType:      models.DataTypeLoginPassword,
			EncryptedData: []byte("data"),
		}
		storage.CreateSecret(s)
	}

	results, err := storage.SearchSecrets("Password")
	if err != nil {
		t.Errorf("SearchSecrets() error = %v", err)
	}

	if len(results) != 1 {
		t.Errorf("SearchSecrets('Password') returned %d results, want 1", len(results))
	}

	results, _ = storage.SearchSecrets("G")
	if len(results) != 2 {
		t.Errorf("SearchSecrets('G') returned %d results, want 2", len(results))
	}
}
