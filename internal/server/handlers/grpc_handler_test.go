package handlers

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/shuklarituparn/Gopherpass/internal/models"
	"github.com/shuklarituparn/Gopherpass/internal/server/auth"
	"github.com/shuklarituparn/Gopherpass/internal/server/service"
	"github.com/shuklarituparn/Gopherpass/internal/server/storage"
	pb "github.com/shuklarituparn/Gopherpass/pkg/proto"
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
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
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
		m.nextID++
		secret.ID = fmt.Sprintf("secret-%d", m.nextID)
	}
	secret.Version = 1
	secret.CreatedAt = time.Now()
	secret.UpdatedAt = time.Now()
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
	return nil, nil
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
	secret.UpdatedAt = time.Now()
	m.secrets[secret.ID] = secret
	return nil
}

func (m *MockStorage) DeleteSecret(ctx context.Context, userID int64, secretID string) error {
	secret, exists := m.secrets[secretID]
	if !exists || secret.UserID != userID || secret.DeletedAt != nil {
		return storage.ErrSecretNotFound
	}
	now := time.Now()
	secret.DeletedAt = &now
	return nil
}

func (m *MockStorage) GetDeletedSecrets(ctx context.Context, userID int64, since time.Time) ([]string, error) {
	return nil, nil
}

func (m *MockStorage) Ping(ctx context.Context) error {
	return nil
}

func (m *MockStorage) Close() error {
	return nil
}

func setupHandler() (*GRPCHandler, *auth.TokenManager) {
	store := NewMockStorage()
	svc := service.NewGophKeeperService(store)
	tm := auth.NewTokenManager("test-secret", time.Hour)
	handler := NewGRPCHandler(svc, tm)
	return handler, tm
}

func TestNewGRPCHandler(t *testing.T) {
	handler, _ := setupHandler()
	if handler == nil {
		t.Error("NewGRPCHandler() returned nil")
	}
}

func TestGRPCHandler_Register(t *testing.T) {
	handler, _ := setupHandler()
	ctx := context.Background()

	tests := []struct {
		name    string
		req     *pb.RegisterRequest
		wantErr bool
	}{
		{
			name:    "valid registration",
			req:     &pb.RegisterRequest{Login: "testuser", Password: "password123"},
			wantErr: false,
		},
		{
			name:    "empty login",
			req:     &pb.RegisterRequest{Login: "", Password: "password123"},
			wantErr: true,
		},
		{
			name:    "empty password",
			req:     &pb.RegisterRequest{Login: "testuser2", Password: ""},
			wantErr: true,
		},
		{
			name:    "weak password",
			req:     &pb.RegisterRequest{Login: "testuser3", Password: "12345"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := handler.Register(ctx, tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Register() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && resp.Token == "" {
				t.Error("Register() returned empty token")
			}
		})
	}
}

func TestGRPCHandler_Login(t *testing.T) {
	handler, _ := setupHandler()
	ctx := context.Background()

	handler.Register(ctx, &pb.RegisterRequest{Login: "testuser", Password: "password123"})

	tests := []struct {
		name    string
		req     *pb.LoginRequest
		wantErr bool
	}{
		{
			name:    "valid login",
			req:     &pb.LoginRequest{Login: "testuser", Password: "password123"},
			wantErr: false,
		},
		{
			name:    "wrong password",
			req:     &pb.LoginRequest{Login: "testuser", Password: "wrongpassword"},
			wantErr: true,
		},
		{
			name:    "nonexistent user",
			req:     &pb.LoginRequest{Login: "nonexistent", Password: "password123"},
			wantErr: true,
		},
		{
			name:    "empty login",
			req:     &pb.LoginRequest{Login: "", Password: "password123"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := handler.Login(ctx, tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Login() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && resp.Token == "" {
				t.Error("Login() returned empty token")
			}
		})
	}
}

func TestGRPCHandler_CreateSecret(t *testing.T) {
	handler, _ := setupHandler()

	ctx := context.Background()
	_, err := handler.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name:          "Test",
		DataType:      pb.DataType_DATA_TYPE_TEXT,
		EncryptedData: []byte("data"),
	})
	if err == nil {
		t.Error("CreateSecret() should fail without auth")
	}

	ctx = context.WithValue(ctx, auth.UserIDKey, int64(1))
	resp, err := handler.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name:          "Test Secret",
		DataType:      pb.DataType_DATA_TYPE_LOGIN_PASSWORD,
		EncryptedData: []byte("encrypted"),
		Metadata:      "test",
	})
	if err != nil {
		t.Errorf("CreateSecret() error = %v", err)
	}
	if resp.Secret == nil {
		t.Error("CreateSecret() returned nil secret")
	}

	_, err = handler.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name:          "",
		DataType:      pb.DataType_DATA_TYPE_TEXT,
		EncryptedData: []byte("data"),
	})
	if err == nil {
		t.Error("CreateSecret() should fail with empty name")
	}
}

func TestGRPCHandler_GetSecret(t *testing.T) {
	handler, _ := setupHandler()
	ctx := context.WithValue(context.Background(), auth.UserIDKey, int64(1))

	createResp, _ := handler.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name:          "Test",
		DataType:      pb.DataType_DATA_TYPE_TEXT,
		EncryptedData: []byte("data"),
	})

	resp, err := handler.GetSecret(ctx, &pb.GetSecretRequest{Id: createResp.Secret.Id})
	if err != nil {
		t.Errorf("GetSecret() error = %v", err)
	}
	if resp.Secret.Name != "Test" {
		t.Errorf("GetSecret() Name = %v", resp.Secret.Name)
	}

	_, err = handler.GetSecret(ctx, &pb.GetSecretRequest{Id: "nonexistent"})
	if err == nil {
		t.Error("GetSecret() should fail for nonexistent secret")
	}

	_, err = handler.GetSecret(ctx, &pb.GetSecretRequest{Id: ""})
	if err == nil {
		t.Error("GetSecret() should fail with empty ID")
	}
}

func TestGRPCHandler_ListSecrets(t *testing.T) {
	handler, _ := setupHandler()
	ctx := context.WithValue(context.Background(), auth.UserIDKey, int64(1))

	handler.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name:          "Secret 1",
		DataType:      pb.DataType_DATA_TYPE_TEXT,
		EncryptedData: []byte("data"),
	})
	handler.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name:          "Secret 2",
		DataType:      pb.DataType_DATA_TYPE_LOGIN_PASSWORD,
		EncryptedData: []byte("data"),
	})

	resp, err := handler.ListSecrets(ctx, &pb.ListSecretsRequest{})
	if err != nil {
		t.Errorf("ListSecrets() error = %v", err)
	}
	if len(resp.Secrets) != 2 {
		t.Errorf("ListSecrets() returned %d secrets, want 2", len(resp.Secrets))
	}

	resp, err = handler.ListSecrets(ctx, &pb.ListSecretsRequest{
		DataType: pb.DataType_DATA_TYPE_TEXT,
	})
	if err != nil {
		t.Errorf("ListSecrets() with filter error = %v", err)
	}
	if len(resp.Secrets) != 1 {
		t.Errorf("ListSecrets() with filter returned %d secrets, want 1", len(resp.Secrets))
	}
}

func TestGRPCHandler_DeleteSecret(t *testing.T) {
	handler, _ := setupHandler()
	ctx := context.WithValue(context.Background(), auth.UserIDKey, int64(1))

	createResp, _ := handler.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name:          "To Delete",
		DataType:      pb.DataType_DATA_TYPE_TEXT,
		EncryptedData: []byte("data"),
	})

	_, err := handler.DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: createResp.Secret.Id})
	if err != nil {
		t.Errorf("DeleteSecret() error = %v", err)
	}

	_, err = handler.DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: "nonexistent"})
	if err == nil {
		t.Error("DeleteSecret() should fail for nonexistent secret")
	}

	_, err = handler.DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: ""})
	if err == nil {
		t.Error("DeleteSecret() should fail with empty ID")
	}
}

func TestDataTypeConversions(t *testing.T) {
	tests := []struct {
		proto pb.DataType
		model models.DataType
	}{
		{pb.DataType_DATA_TYPE_LOGIN_PASSWORD, models.DataTypeLoginPassword},
		{pb.DataType_DATA_TYPE_TEXT, models.DataTypeText},
		{pb.DataType_DATA_TYPE_BINARY, models.DataTypeBinary},
		{pb.DataType_DATA_TYPE_CARD, models.DataTypeCard},
		{pb.DataType_DATA_TYPE_UNSPECIFIED, models.DataType(0)},
	}

	for _, tt := range tests {
		got := protoToModelDataType(tt.proto)
		if got != tt.model {
			t.Errorf("protoToModelDataType(%v) = %v, want %v", tt.proto, got, tt.model)
		}

		gotProto := modelToProtoDataType(tt.model)
		if gotProto != tt.proto {
			t.Errorf("modelToProtoDataType(%v) = %v, want %v", tt.model, gotProto, tt.proto)
		}
	}
}

func TestSecretConversions(t *testing.T) {
	now := time.Now()
	modelSecret := &models.Secret{
		ID:            "test-id",
		UserID:        1,
		Name:          "Test",
		DataType:      models.DataTypeText,
		EncryptedData: []byte("data"),
		Metadata:      "meta",
		Version:       1,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	protoSecret := modelToProtoSecret(modelSecret)
	if protoSecret.Id != "test-id" {
		t.Errorf("modelToProtoSecret().Id = %v", protoSecret.Id)
	}
	if protoSecret.Name != "Test" {
		t.Errorf("modelToProtoSecret().Name = %v", protoSecret.Name)
	}

	backToModel := protoToModelSecret(protoSecret)
	if backToModel.ID != "test-id" {
		t.Errorf("protoToModelSecret().ID = %v", backToModel.ID)
	}

	if modelToProtoSecret(nil) != nil {
		t.Error("modelToProtoSecret(nil) should return nil")
	}
	if protoToModelSecret(nil) != nil {
		t.Error("protoToModelSecret(nil) should return nil")
	}
}
