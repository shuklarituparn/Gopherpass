package service

import (
	"context"
	"errors"
	"time"

	"github.com/shuklarituparn/Gopherpass/internal/crypto"
	"github.com/shuklarituparn/Gopherpass/internal/models"
	"github.com/shuklarituparn/Gopherpass/internal/server/storage"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserExists         = errors.New("user already exists")
	ErrWeakPassword       = errors.New("password is too weak")
	ErrInvalidLogin       = errors.New("login is invalid")
)

type GophKeeperService struct {
	storage storage.Storage
}

func NewGophKeeperService(storage storage.Storage) *GophKeeperService {
	return &GophKeeperService{
		storage: storage,
	}
}

func (s *GophKeeperService) Register(ctx context.Context, login, password string) (*models.User, error) {
	if len(login) < 3 || len(login) > 50 {
		return nil, ErrInvalidLogin
	}

	if len(password) < 6 {
		return nil, ErrWeakPassword
	}

	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		return nil, err
	}

	user := &models.User{
		Login:        login,
		PasswordHash: hashedPassword,
	}

	if err := s.storage.CreateUser(ctx, user); err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			return nil, ErrUserExists
		}
		return nil, err
	}

	return user, nil
}

func (s *GophKeeperService) Login(ctx context.Context, login, password string) (*models.User, error) {
	user, err := s.storage.GetUserByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if err := crypto.CheckPassword(password, user.PasswordHash); err != nil {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

func (s *GophKeeperService) CreateSecret(ctx context.Context, secret *models.Secret) error {
	return s.storage.CreateSecret(ctx, secret)
}

func (s *GophKeeperService) GetSecret(ctx context.Context, userID int64, secretID string) (*models.Secret, error) {
	return s.storage.GetSecret(ctx, userID, secretID)
}

func (s *GophKeeperService) ListSecrets(ctx context.Context, userID int64) ([]models.Secret, error) {
	return s.storage.GetSecretsByUser(ctx, userID)
}

func (s *GophKeeperService) ListSecretsOfType(ctx context.Context, userID int64, dataType models.DataType) ([]models.Secret, error) {
	secrets, err := s.storage.GetSecretsByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	var filtered []models.Secret
	for _, secret := range secrets {
		if secret.DataType == dataType {
			filtered = append(filtered, secret)
		}
	}

	return filtered, nil
}

func (s *GophKeeperService) UpdateSecret(ctx context.Context, secret *models.Secret) error {
	return s.storage.UpdateSecret(ctx, secret)
}

func (s *GophKeeperService) DeleteSecret(ctx context.Context, userID int64, secretID string) error {
	return s.storage.DeleteSecret(ctx, userID, secretID)
}

type SyncRequest struct {
	UserID       int64
	LastSyncTime time.Time
	LocalChanges []models.Secret
}

type SyncResult struct {
	UpdatedSecrets []models.Secret
	DeletedIDs     []string
	ServerTime     time.Time
	HasConflicts   bool
	Conflicts      []SyncConflict
}

type SyncConflict struct {
	SecretID      string
	ClientVersion models.Secret
	ServerVersion models.Secret
}

func (s *GophKeeperService) Sync(ctx context.Context, req *SyncRequest) (*SyncResult, error) {
	result := &SyncResult{
		ServerTime: time.Now(),
	}

	for _, localSecret := range req.LocalChanges {
		localSecret.UserID = req.UserID

		existing, err := s.storage.GetSecret(ctx, req.UserID, localSecret.ID)
		if err != nil {
			if errors.Is(err, storage.ErrSecretNotFound) {
				if err := s.storage.CreateSecret(ctx, &localSecret); err != nil {
					return nil, err
				}
				continue
			}
			return nil, err
		}

		if existing.Version != localSecret.Version {
			result.HasConflicts = true
			result.Conflicts = append(result.Conflicts, SyncConflict{
				SecretID:      localSecret.ID,
				ClientVersion: localSecret,
				ServerVersion: *existing,
			})
			continue
		}

		if localSecret.DeletedAt != nil {
			if err := s.storage.DeleteSecret(ctx, req.UserID, localSecret.ID); err != nil {
				return nil, err
			}
		} else {
			if err := s.storage.UpdateSecret(ctx, &localSecret); err != nil {
				return nil, err
			}
		}
	}

	serverSecrets, err := s.storage.GetSecretsModifiedSince(ctx, req.UserID, req.LastSyncTime)
	if err != nil {
		return nil, err
	}
	result.UpdatedSecrets = serverSecrets

	deletedIDs, err := s.storage.GetDeletedSecrets(ctx, req.UserID, req.LastSyncTime)
	if err != nil {
		return nil, err
	}
	result.DeletedIDs = deletedIDs

	return result, nil
}

func (s *GophKeeperService) GetUser(ctx context.Context, userID int64) (*models.User, error) {
	return s.storage.GetUserByID(ctx, userID)
}
