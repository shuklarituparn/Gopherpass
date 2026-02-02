package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/shuklarituparn/Gopherpass/internal/models"
	pb "github.com/shuklarituparn/Gopherpass/pkg/proto"
)

var (
	ErrNotConnected    = errors.New("not connected to server")
	ErrNotAuthenticated = errors.New("not authenticated")
)

type Client struct {
	conn    *grpc.ClientConn
	client  pb.GophKeeperClient
	token   string
	timeout time.Duration
}

type ClientOptions struct {
	Address     string
	UseTLS      bool
	TLSCertFile string
	Timeout     time.Duration
}

func NewClient(opts *ClientOptions) (*Client, error) {
	var dialOpts []grpc.DialOption

	if opts.UseTLS {
		var tlsConfig *tls.Config
		if opts.TLSCertFile != "" {
			caCert, err := os.ReadFile(opts.TLSCertFile)
			if err != nil {
				return nil, err
			}
			certPool := x509.NewCertPool()
			certPool.AppendCertsFromPEM(caCert)
			tlsConfig = &tls.Config{RootCAs: certPool}
		} else {
			tlsConfig = &tls.Config{}
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(opts.Address, dialOpts...)
	if err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &Client{
		conn:    conn,
		client:  pb.NewGophKeeperClient(conn),
		timeout: timeout,
	}, nil
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) SetToken(token string) {
	c.token = token
}

func (c *Client) getContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	if c.token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
	}
	return ctx, cancel
}


func (c *Client) requireAuth() error {
	if c.token == "" {
		return ErrNotAuthenticated
	}
	return nil
}


func (c *Client) withAuth(operation func() error) error {
	if err := c.requireAuth(); err != nil {
		return err
	}
	return operation()
}

func (c *Client) Register(login, password string) (*models.RegisterResponse, error) {
	ctx, cancel := c.getContext()
	defer cancel()

	resp, err := c.client.Register(ctx, &pb.RegisterRequest{
		Login:    login,
		Password: password,
	})
	if err != nil {
		return nil, err
	}

	c.token = resp.Token

	return &models.RegisterResponse{
		UserID: resp.UserId,
		Token:  resp.Token,
	}, nil
}

func (c *Client) Login(login, password string) (*models.AuthResponse, error) {
	ctx, cancel := c.getContext()
	defer cancel()

	resp, err := c.client.Login(ctx, &pb.LoginRequest{
		Login:    login,
		Password: password,
	})
	if err != nil {
		return nil, err
	}

	c.token = resp.Token

	return &models.AuthResponse{
		Token:     resp.Token,
		ExpiresAt: time.Unix(resp.ExpiresAt, 0),
		UserID:    resp.UserId,
	}, nil
}

func (c *Client) CreateSecret(name string, dataType models.DataType, encryptedData []byte, metadata string) (*models.Secret, error) {
	if err := c.requireAuth(); err != nil {
		return nil, err
	}

	ctx, cancel := c.getContext()
	defer cancel()

	resp, err := c.client.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name:          name,
		DataType:      modelToProtoDataType(dataType),
		EncryptedData: encryptedData,
		Metadata:      metadata,
	})
	if err != nil {
		return nil, err
	}

	return protoToModelSecret(resp.Secret), nil
}

func (c *Client) GetSecret(id string) (*models.Secret, error) {
	if err := c.requireAuth(); err != nil {
		return nil, err
	}

	ctx, cancel := c.getContext()
	defer cancel()

	resp, err := c.client.GetSecret(ctx, &pb.GetSecretRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}

	return protoToModelSecret(resp.Secret), nil
}

func (c *Client) ListSecrets(dataType *models.DataType) ([]models.Secret, error) {
	if err := c.requireAuth(); err != nil {
		return nil, err
	}

	ctx, cancel := c.getContext()
	defer cancel()

	req := &pb.ListSecretsRequest{}
	if dataType != nil {
		req.DataType = modelToProtoDataType(*dataType)
	}

	resp, err := c.client.ListSecrets(ctx, req)
	if err != nil {
		return nil, err
	}

	secrets := make([]models.Secret, len(resp.Secrets))
	for i, s := range resp.Secrets {
		secrets[i] = *protoToModelSecret(s)
	}

	return secrets, nil
}

func (c *Client) UpdateSecret(secret *models.Secret) (*models.Secret, error) {
	if err := c.requireAuth(); err != nil {
		return nil, err
	}

	ctx, cancel := c.getContext()
	defer cancel()

	resp, err := c.client.UpdateSecret(ctx, &pb.UpdateSecretRequest{
		Id:              secret.ID,
		Name:            secret.Name,
		EncryptedData:   secret.EncryptedData,
		Metadata:        secret.Metadata,
		ExpectedVersion: secret.Version,
	})
	if err != nil {
		return nil, err
	}

	return protoToModelSecret(resp.Secret), nil
}

func (c *Client) DeleteSecret(id string) error {
	if err := c.requireAuth(); err != nil {
		return err
	}

	ctx, cancel := c.getContext()
	defer cancel()

	_, err := c.client.DeleteSecret(ctx, &pb.DeleteSecretRequest{
		Id: id,
	})
	return err
}

func (c *Client) Sync(lastSyncTime time.Time, localChanges []models.Secret) (*models.SyncResponse, error) {
	if err := c.requireAuth(); err != nil {
		return nil, err
	}

	ctx, cancel := c.getContext()
	defer cancel()

	protoChanges := make([]*pb.Secret, len(localChanges))
	for i, s := range localChanges {
		protoChanges[i] = modelToProtoSecret(&s)
	}

	resp, err := c.client.Sync(ctx, &pb.SyncRequest{
		LastSyncTime: lastSyncTime.Unix(),
		LocalChanges: protoChanges,
	})
	if err != nil {
		return nil, err
	}

	updatedSecrets := make([]models.Secret, len(resp.UpdatedSecrets))
	for i, s := range resp.UpdatedSecrets {
		updatedSecrets[i] = *protoToModelSecret(s)
	}

	return &models.SyncResponse{
		UpdatedSecrets: updatedSecrets,
		DeletedIDs:     resp.DeletedIds,
		ServerTime:     time.Unix(resp.ServerTime, 0),
		HasConflicts:   resp.HasConflicts,
	}, nil
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