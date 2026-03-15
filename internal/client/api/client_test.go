package api

import (
	"testing"
	"time"

	"github.com/shuklarituparn/Gopherpass/internal/models"
)

func TestClientErrors(t *testing.T) {
	if ErrNotConnected.Error() != "not connected to server" {
		t.Errorf("ErrNotConnected = %v", ErrNotConnected)
	}
	if ErrNotAuthenticated.Error() != "not authenticated" {
		t.Errorf("ErrNotAuthenticated = %v", ErrNotAuthenticated)
	}
}

func TestClientOptions(t *testing.T) {
	opts := &ClientOptions{
		Address:     "localhost:3200",
		UseTLS:      false,
		TLSCertFile: "",
		Timeout:     30 * time.Second,
	}

	if opts.Address != "localhost:3200" {
		t.Errorf("ClientOptions.Address = %v", opts.Address)
	}
}

func TestModelToProtoDataType(t *testing.T) {
	tests := []struct {
		model models.DataType
		want  int
	}{
		{models.DataTypeLoginPassword, 1},
		{models.DataTypeText, 2},
		{models.DataTypeBinary, 3},
		{models.DataTypeCard, 4},
		{models.DataType(0), 0},
		{models.DataType(99), 0},
	}

	for _, tt := range tests {
		got := modelToProtoDataType(tt.model)
		if int(got) != tt.want {
			t.Errorf("modelToProtoDataType(%v) = %v, want %v", tt.model, got, tt.want)
		}
	}
}

func TestProtoToModelDataType(t *testing.T) {
	types := []models.DataType{
		models.DataTypeLoginPassword,
		models.DataTypeText,
		models.DataTypeBinary,
		models.DataTypeCard,
	}

	for _, dt := range types {
		proto := modelToProtoDataType(dt)
		back := protoToModelDataType(proto)
		if back != dt {
			t.Errorf("round-trip failed for %v: got %v", dt, back)
		}
	}
}

func TestModelToProtoSecret(t *testing.T) {
	now := time.Now()
	secret := &models.Secret{
		ID:            "test-id",
		UserID:        1,
		Name:          "Test Secret",
		DataType:      models.DataTypeText,
		EncryptedData: []byte("encrypted"),
		Metadata:      "meta",
		Version:       1,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	proto := modelToProtoSecret(secret)
	if proto == nil {
		t.Fatal("modelToProtoSecret() returned nil")
	}

	if proto.Id != "test-id" {
		t.Errorf("proto.Id = %v", proto.Id)
	}
	if proto.Name != "Test Secret" {
		t.Errorf("proto.Name = %v", proto.Name)
	}
	if proto.UserId != 1 {
		t.Errorf("proto.UserId = %v", proto.UserId)
	}

	if modelToProtoSecret(nil) != nil {
		t.Error("modelToProtoSecret(nil) should return nil")
	}
}

func TestProtoToModelSecret(t *testing.T) {
	if protoToModelSecret(nil) != nil {
		t.Error("protoToModelSecret(nil) should return nil")
	}
}

func TestClient_SetToken(t *testing.T) {
	c := &Client{}
	c.SetToken("test-token")
	if c.token != "test-token" {
		t.Errorf("SetToken() token = %v", c.token)
	}
}

func TestNewClient_InvalidAddress(t *testing.T) {
	opts := &ClientOptions{
		Address: "localhost:3200",
		UseTLS:  false,
		Timeout: time.Second,
	}

	client, err := NewClient(opts)
	if err != nil {
		t.Skipf("Skipping - could not create client: %v", err)
	}
	if client == nil {
		t.Error("NewClient() returned nil client")
	}
	if client != nil {
		client.Close()
	}
}

func TestClient_NotAuthenticated(t *testing.T) {
	c := &Client{token: ""}

	_, err := c.CreateSecret("test", models.DataTypeText, []byte("data"), "")
	if err != ErrNotAuthenticated {
		t.Errorf("CreateSecret() error = %v, want ErrNotAuthenticated", err)
	}

	_, err = c.GetSecret("id")
	if err != ErrNotAuthenticated {
		t.Errorf("GetSecret() error = %v, want ErrNotAuthenticated", err)
	}

	_, err = c.ListSecrets(nil)
	if err != ErrNotAuthenticated {
		t.Errorf("ListSecrets() error = %v, want ErrNotAuthenticated", err)
	}

	_, err = c.UpdateSecret(&models.Secret{})
	if err != ErrNotAuthenticated {
		t.Errorf("UpdateSecret() error = %v, want ErrNotAuthenticated", err)
	}

	err = c.DeleteSecret("id")
	if err != ErrNotAuthenticated {
		t.Errorf("DeleteSecret() error = %v, want ErrNotAuthenticated", err)
	}

	_, err = c.Sync(time.Now(), nil)
	if err != ErrNotAuthenticated {
		t.Errorf("Sync() error = %v, want ErrNotAuthenticated", err)
	}
}
