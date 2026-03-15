package service

import (
	"context"
	"testing"
	"time"

	"github.com/shuklarituparn/Gopherpass/internal/models"
	"github.com/shuklarituparn/Gopherpass/internal/server/storage"
)

type MockStorage struct {
	users   map[string]*models.User
	secrets map[string]*models.Secret
	nextID  int64
}

func NewMockStorage() *MockStorage {
	return &MockStorage{
		users:   make(map[string]*models.User),
		secrets: make(map[string]*models.Secret),
		nextID:  1,
	}
}

func (m *MockStorage) CreateUser(ctx context.Context, user *models.User) error {
	if _, exists := m.users[user.Login]; exists {
		return storage.ErrUserExists
	}
	user.ID = m.nextID
	m.nextID++
	m.users[user.Login] = user
	return nil
}

func (m *MockStorage) GetUserByLogin(ctx context.Context, login string) (*models.User, error) {
	user, exists := m.users[login]
	if !exists {
		return nil, storage.ErrUserNotFound
	}
	return user, nil
}

func (m *MockStorage) GetUserByID(ctx context.Context, id int64) (*models.User, error) {
	for _, user := range m.users {
		if user.ID == id {
			return user, nil
		}
	}
	return nil, storage.ErrUserNotFound
}

func (m *MockStorage) CreateSecret(ctx context.Context, secret *models.Secret) error {
	if secret.ID == "" {
		secret.ID = "secret-" + string(rune(len(m.secrets)+1))
	}
	m.secrets[secret.ID] = secret
	return nil
}

func (m *MockStorage) GetSecret(ctx context.Context, userID int64, secretID string) (*models.Secret, error) {
	secret, exists := m.secrets[secretID]
	if !exists || secret.UserID != userID {
		return nil, storage.ErrSecretNotFound
	}
	return secret, nil
}

func (m *MockStorage) GetSecretsByUser(ctx context.Context, userID int64) ([]models.Secret, error) {
	var result []models.Secret
	for _, secret := range m.secrets {
		if secret.UserID == userID && secret.DeletedAt == nil {
			result = append(result, *secret)
		}
	}
	return result, nil
}

func (m *MockStorage) GetSecretsModifiedSince(ctx context.Context, userID int64, since time.Time) ([]models.Secret, error) {
	var result []models.Secret
	for _, secret := range m.secrets {
		if secret.UserID == userID && secret.UpdatedAt.After(since) {
			result = append(result, *secret)
		}
	}
	return result, nil
}

func (m *MockStorage) UpdateSecret(ctx context.Context, secret *models.Secret) error {
	existing, exists := m.secrets[secret.ID]
	if !exists || existing.UserID != secret.UserID {
		return storage.ErrSecretNotFound
	}
	if existing.Version != secret.Version {
		return storage.ErrVersionConflict
	}
	secret.Version++
	m.secrets[secret.ID] = secret
	return nil
}

func (m *MockStorage) DeleteSecret(ctx context.Context, userID int64, secretID string) error {
	secret, exists := m.secrets[secretID]
	if !exists || secret.UserID != userID {
		return storage.ErrSecretNotFound
	}
	now := time.Now()
	secret.DeletedAt = &now
	return nil
}

func (m *MockStorage) GetDeletedSecrets(ctx context.Context, userID int64, since time.Time) ([]string, error) {
	var result []string
	for id, secret := range m.secrets {
		if secret.UserID == userID && secret.DeletedAt != nil && secret.DeletedAt.After(since) {
			result = append(result, id)
		}
	}
	return result, nil
}

func (m *MockStorage) Ping(ctx context.Context) error {
	return nil
}

func (m *MockStorage) Close() error {
	return nil
}

func TestNewGophKeeperService(t *testing.T) {
	store := NewMockStorage()
	svc := NewGophKeeperService(store)
	if svc == nil {
		t.Error("NewGophKeeperService() returned nil")
	}
}

func TestGophKeeperService_Register(t *testing.T) {
	store := NewMockStorage()
	svc := NewGophKeeperService(store)
	ctx := context.Background()

	tests := []struct {
		name     string
		login    string
		password string
		wantErr  error
	}{
		{
			name:     "valid registration",
			login:    "testuser",
			password: "password123",
			wantErr:  nil,
		},
		{
			name:     "short login",
			login:    "ab",
			password: "password123",
			wantErr:  ErrInvalidLogin,
		},
		{
			name:     "weak password",
			login:    "testuser2",
			password: "12345",
			wantErr:  ErrWeakPassword,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := svc.Register(ctx, tt.login, tt.password)
			if err != tt.wantErr {
				t.Errorf("Register() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == nil && user == nil {
				t.Error("Register() returned nil user on success")
			}
		})
	}
}

func TestGophKeeperService_Register_Duplicate(t *testing.T) {
	store := NewMockStorage()
	svc := NewGophKeeperService(store)
	ctx := context.Background()

	_, err := svc.Register(ctx, "testuser", "password123")
	if err != nil {
		t.Fatalf("First Register() error = %v", err)
	}

	_, err = svc.Register(ctx, "testuser", "password456")
	if err != ErrUserExists {
		t.Errorf("Register() error = %v, want ErrUserExists", err)
	}
}

func TestGophKeeperService_Login(t *testing.T) {
	store := NewMockStorage()
	svc := NewGophKeeperService(store)
	ctx := context.Background()

	_, err := svc.Register(ctx, "testuser", "password123")
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	tests := []struct {
		name     string
		login    string
		password string
		wantErr  error
	}{
		{
			name:     "valid login",
			login:    "testuser",
			password: "password123",
			wantErr:  nil,
		},
		{
			name:     "wrong password",
			login:    "testuser",
			password: "wrongpassword",
			wantErr:  ErrInvalidCredentials,
		},
		{
			name:     "nonexistent user",
			login:    "nonexistent",
			password: "password123",
			wantErr:  ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := svc.Login(ctx, tt.login, tt.password)
			if err != tt.wantErr {
				t.Errorf("Login() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr == nil && user == nil {
				t.Error("Login() returned nil user on success")
			}
		})
	}
}

func TestGophKeeperService_SecretOperations(t *testing.T) {
	store := NewMockStorage()
	svc := NewGophKeeperService(store)
	ctx := context.Background()

	secret := &models.Secret{
		UserID:        1,
		Name:          "Test Secret",
		DataType:      models.DataTypeLoginPassword,
		EncryptedData: []byte("encrypted"),
		Metadata:      "test",
	}

	err := svc.CreateSecret(ctx, secret)
	if err != nil {
		t.Fatalf("CreateSecret() error = %v", err)
	}

	if secret.ID == "" {
		t.Error("CreateSecret() did not set ID")
	}

	retrieved, err := svc.GetSecret(ctx, 1, secret.ID)
	if err != nil {
		t.Errorf("GetSecret() error = %v", err)
	}
	if retrieved.Name != "Test Secret" {
		t.Errorf("GetSecret() Name = %v, want Test Secret", retrieved.Name)
	}

	secrets, err := svc.ListSecrets(ctx, 1)
	if err != nil {
		t.Errorf("ListSecrets() error = %v", err)
	}
	if len(secrets) != 1 {
		t.Errorf("ListSecrets() returned %d secrets, want 1", len(secrets))
	}

	secrets, err = svc.ListSecretsOfType(ctx, 1, models.DataTypeLoginPassword)
	if err != nil {
		t.Errorf("ListSecretsOfType() error = %v", err)
	}
	if len(secrets) != 1 {
		t.Errorf("ListSecretsOfType() returned %d secrets, want 1", len(secrets))
	}

	err = svc.DeleteSecret(ctx, 1, secret.ID)
	if err != nil {
		t.Errorf("DeleteSecret() error = %v", err)
	}
}

func TestGophKeeperService_GetUser(t *testing.T) {
	store := NewMockStorage()
	svc := NewGophKeeperService(store)
	ctx := context.Background()

	user, _ := svc.Register(ctx, "testuser", "password123")

	retrieved, err := svc.GetUser(ctx, user.ID)
	if err != nil {
		t.Errorf("GetUser() error = %v", err)
	}
	if retrieved.Login != "testuser" {
		t.Errorf("GetUser() Login = %v, want testuser", retrieved.Login)
	}

	_, err = svc.GetUser(ctx, 999)
	if err != storage.ErrUserNotFound {
		t.Errorf("GetUser() error = %v, want ErrUserNotFound", err)
	}
}
