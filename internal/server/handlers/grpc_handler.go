package handlers

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/shuklarituparn/Gopherpass/internal/models"
	"github.com/shuklarituparn/Gopherpass/internal/server/auth"
	"github.com/shuklarituparn/Gopherpass/internal/server/service"
	"github.com/shuklarituparn/Gopherpass/internal/server/storage"
	pb "github.com/shuklarituparn/Gopherpass/pkg/proto"
)

type GRPCHandler struct {
	pb.UnimplementedGophKeeperServer
	service      *service.GophKeeperService
	tokenManager *auth.TokenManager
}

func NewGRPCHandler(svc *service.GophKeeperService, tokenManager *auth.TokenManager) *GRPCHandler {
	return &GRPCHandler{
		service:      svc,
		tokenManager: tokenManager,
	}
}

func (h *GRPCHandler) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if req.Login == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "login and password are required")
	}

	user, err := h.service.Register(ctx, req.Login, req.Password)
	if err != nil {
		switch err {
		case service.ErrUserExists:
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		case service.ErrWeakPassword:
			return nil, status.Error(codes.InvalidArgument, "password is too weak (min 6 characters)")
		case service.ErrInvalidLogin:
			return nil, status.Error(codes.InvalidArgument, "invalid login (3-50 characters)")
		default:
			return nil, status.Error(codes.Internal, "failed to register user")
		}
	}

	token, _, err := h.tokenManager.GenerateToken(user.ID, user.Login)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate token")
	}

	return &pb.RegisterResponse{
		UserId: user.ID,
		Token:  token,
	}, nil
}

func (h *GRPCHandler) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	if req.Login == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "login and password are required")
	}

	user, err := h.service.Login(ctx, req.Login, req.Password)
	if err != nil {
		if err == service.ErrInvalidCredentials {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "authentication failed")
	}

	token, expiresAt, err := h.tokenManager.GenerateToken(user.ID, user.Login)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to generate token")
	}

	return &pb.LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt.Unix(),
		UserId:    user.ID,
	}, nil
}

func (h *GRPCHandler) CreateSecret(ctx context.Context, req *pb.CreateSecretRequest) (*pb.CreateSecretResponse, error) {
	userID, ok := auth.GetUserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}

	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "secret name is required")
	}

	secret := &models.Secret{
		UserID:        userID,
		Name:          req.Name,
		DataType:      protoToModelDataType(req.DataType),
		EncryptedData: req.EncryptedData,
		Metadata:      req.Metadata,
	}

	if err := h.service.CreateSecret(ctx, secret); err != nil {
		return nil, status.Error(codes.Internal, "failed to create secret")
	}

	return &pb.CreateSecretResponse{
		Secret: modelToProtoSecret(secret),
	}, nil
}

func (h *GRPCHandler) GetSecret(ctx context.Context, req *pb.GetSecretRequest) (*pb.GetSecretResponse, error) {
	userID, ok := auth.GetUserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}

	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "secret ID is required")
	}

	secret, err := h.service.GetSecret(ctx, userID, req.Id)
	if err != nil {
		if err == storage.ErrSecretNotFound {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		return nil, status.Error(codes.Internal, "failed to get secret")
	}

	return &pb.GetSecretResponse{
		Secret: modelToProtoSecret(secret),
	}, nil
}

func (h *GRPCHandler) ListSecrets(ctx context.Context, req *pb.ListSecretsRequest) (*pb.ListSecretsResponse, error) {
	userID, ok := auth.GetUserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}

	var secrets []models.Secret
	var err error

	if req.DataType != pb.DataType_DATA_TYPE_UNSPECIFIED {
		secrets, err = h.service.ListSecretsOfType(ctx, userID, protoToModelDataType(req.DataType))
	} else {
		secrets, err = h.service.ListSecrets(ctx, userID)
	}

	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list secrets")
	}

	protoSecrets := make([]*pb.Secret, len(secrets))
	for i, secret := range secrets {
		protoSecrets[i] = modelToProtoSecret(&secret)
	}

	return &pb.ListSecretsResponse{
		Secrets: protoSecrets,
	}, nil
}

// UpdateSecret updates an existing secret.
func (h *GRPCHandler) UpdateSecret(ctx context.Context, req *pb.UpdateSecretRequest) (*pb.UpdateSecretResponse, error) {
	userID, ok := auth.GetUserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}

	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "secret ID is required")
	}

	secret := &models.Secret{
		ID:            req.Id,
		UserID:        userID,
		Name:          req.Name,
		EncryptedData: req.EncryptedData,
		Metadata:      req.Metadata,
		Version:       req.ExpectedVersion,
	}

	if err := h.service.UpdateSecret(ctx, secret); err != nil {
		switch err {
		case storage.ErrSecretNotFound:
			return nil, status.Error(codes.NotFound, "secret not found")
		case storage.ErrVersionConflict:
			return nil, status.Error(codes.FailedPrecondition, "version conflict")
		default:
			return nil, status.Error(codes.Internal, "failed to update secret")
		}
	}

	return &pb.UpdateSecretResponse{
		Secret: modelToProtoSecret(secret),
	}, nil
}

func (h *GRPCHandler) DeleteSecret(ctx context.Context, req *pb.DeleteSecretRequest) (*pb.DeleteSecretResponse, error) {
	userID, ok := auth.GetUserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}

	if req.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "secret ID is required")
	}

	if err := h.service.DeleteSecret(ctx, userID, req.Id); err != nil {
		if err == storage.ErrSecretNotFound {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		return nil, status.Error(codes.Internal, "failed to delete secret")
	}

	return &pb.DeleteSecretResponse{}, nil
}

func (h *GRPCHandler) Sync(ctx context.Context, req *pb.SyncRequest) (*pb.SyncResponse, error) {
	userID, ok := auth.GetUserIDFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}

	localChanges := make([]models.Secret, len(req.LocalChanges))
	for i, protoSecret := range req.LocalChanges {
		localChanges[i] = *protoToModelSecret(protoSecret)
	}

	syncReq := &service.SyncRequest{
		UserID:       userID,
		LastSyncTime: time.Unix(req.LastSyncTime, 0),
		LocalChanges: localChanges,
	}

	result, err := h.service.Sync(ctx, syncReq)
	if err != nil {
		return nil, status.Error(codes.Internal, "sync failed")
	}

	protoSecrets := make([]*pb.Secret, len(result.UpdatedSecrets))
	for i, secret := range result.UpdatedSecrets {
		protoSecrets[i] = modelToProtoSecret(&secret)
	}

	protoConflicts := make([]*pb.SyncConflict, len(result.Conflicts))
	for i, conflict := range result.Conflicts {
		protoConflicts[i] = &pb.SyncConflict{
			SecretId:      conflict.SecretID,
			ClientVersion: modelToProtoSecret(&conflict.ClientVersion),
			ServerVersion: modelToProtoSecret(&conflict.ServerVersion),
		}
	}

	return &pb.SyncResponse{
		UpdatedSecrets: protoSecrets,
		DeletedIds:     result.DeletedIDs,
		ServerTime:     result.ServerTime.Unix(),
		HasConflicts:   result.HasConflicts,
		Conflicts:      protoConflicts,
	}, nil
}


func protoToModelDataType(dt pb.DataType) models.DataType {
	switch dt {
	case pb.DataType_DATA_TYPE_LOGIN_PASSWORD:
		return models.DataTypeLoginPassword
	case pb.DataType_DATA_TYPE_TEXT:
		return models.DataTypeText
	case pb.DataType_DATA_TYPE_BINARY:
		return models.DataTypeBinary
	case pb.DataType_DATA_TYPE_CARD:
		return models.DataTypeCard
	default:
		return 0
	}
}

func modelToProtoDataType(dt models.DataType) pb.DataType {
	switch dt {
	case models.DataTypeLoginPassword:
		return pb.DataType_DATA_TYPE_LOGIN_PASSWORD
	case models.DataTypeText:
		return pb.DataType_DATA_TYPE_TEXT
	case models.DataTypeBinary:
		return pb.DataType_DATA_TYPE_BINARY
	case models.DataTypeCard:
		return pb.DataType_DATA_TYPE_CARD
	default:
		return pb.DataType_DATA_TYPE_UNSPECIFIED
	}
}

func modelToProtoSecret(s *models.Secret) *pb.Secret {
	if s == nil {
		return nil
	}
	return &pb.Secret{
		Id:            s.ID,
		UserId:        s.UserID,
		Name:          s.Name,
		DataType:      modelToProtoDataType(s.DataType),
		EncryptedData: s.EncryptedData,
		Metadata:      s.Metadata,
		Version:       s.Version,
		CreatedAt:     s.CreatedAt.Unix(),
		UpdatedAt:     s.UpdatedAt.Unix(),
		Deleted:       s.DeletedAt != nil,
	}
}

func protoToModelSecret(s *pb.Secret) *models.Secret {
	if s == nil {
		return nil
	}
	secret := &models.Secret{
		ID:            s.Id,
		UserID:        s.UserId,
		Name:          s.Name,
		DataType:      protoToModelDataType(s.DataType),
		EncryptedData: s.EncryptedData,
		Metadata:      s.Metadata,
		Version:       s.Version,
		CreatedAt:     time.Unix(s.CreatedAt, 0),
		UpdatedAt:     time.Unix(s.UpdatedAt, 0),
	}
	if s.Deleted {
		now := time.Now()
		secret.DeletedAt = &now
	}
	return secret
}
