package models

import (
	"testing"
	"time"
)

func TestDataType_String(t *testing.T) {
	tests := []struct {
		dt   DataType
		want string
	}{
		{DataTypeLoginPassword, "login_password"},
		{DataTypeText, "text"},
		{DataTypeBinary, "binary"},
		{DataTypeCard, "card"},
		{DataType(0), "unknown"},
		{DataType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.dt.String(); got != tt.want {
				t.Errorf("DataType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseDataType(t *testing.T) {
	tests := []struct {
		s    string
		want DataType
	}{
		{"login_password", DataTypeLoginPassword},
		{"text", DataTypeText},
		{"binary", DataTypeBinary},
		{"card", DataTypeCard},
		{"unknown", DataType(0)},
		{"invalid", DataType(0)},
		{"", DataType(0)},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			if got := ParseDataType(tt.s); got != tt.want {
				t.Errorf("ParseDataType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUser(t *testing.T) {
	now := time.Now()
	user := User{
		ID:           1,
		Login:        "testuser",
		PasswordHash: "hash123",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if user.ID != 1 {
		t.Errorf("User.ID = %v, want 1", user.ID)
	}
	if user.Login != "testuser" {
		t.Errorf("User.Login = %v, want testuser", user.Login)
	}
}

func TestSecret(t *testing.T) {
	now := time.Now()
	secret := Secret{
		ID:            "secret-123",
		UserID:        1,
		Name:          "My Secret",
		DataType:      DataTypeLoginPassword,
		EncryptedData: []byte("encrypted"),
		Metadata:      "test metadata",
		Version:       1,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if secret.ID != "secret-123" {
		t.Errorf("Secret.ID = %v, want secret-123", secret.ID)
	}
	if secret.DataType != DataTypeLoginPassword {
		t.Errorf("Secret.DataType = %v, want %v", secret.DataType, DataTypeLoginPassword)
	}
	if secret.DeletedAt != nil {
		t.Error("Secret.DeletedAt should be nil")
	}
}

func TestLoginPassword(t *testing.T) {
	lp := LoginPassword{
		Login:    "user@example.com",
		Password: "secret123",
		URL:      "https://example.com",
	}

	if lp.Login != "user@example.com" {
		t.Errorf("LoginPassword.Login = %v, want user@example.com", lp.Login)
	}
}

func TestTextData(t *testing.T) {
	td := TextData{
		Text: "This is my secure note",
	}

	if td.Text != "This is my secure note" {
		t.Errorf("TextData.Text = %v, want 'This is my secure note'", td.Text)
	}
}

func TestBinaryData(t *testing.T) {
	bd := BinaryData{
		Data:     []byte{1, 2, 3, 4, 5},
		FileName: "test.bin",
	}

	if len(bd.Data) != 5 {
		t.Errorf("BinaryData.Data length = %v, want 5", len(bd.Data))
	}
	if bd.FileName != "test.bin" {
		t.Errorf("BinaryData.FileName = %v, want test.bin", bd.FileName)
	}
}

func TestCardData(t *testing.T) {
	cd := CardData{
		Number:     "4111111111111111",
		Holder:     "JOHN DOE",
		ExpiryDate: "12/25",
		CVV:        "123",
	}

	if cd.Number != "4111111111111111" {
		t.Errorf("CardData.Number = %v", cd.Number)
	}
	if cd.Holder != "JOHN DOE" {
		t.Errorf("CardData.Holder = %v", cd.Holder)
	}
	if cd.ExpiryDate != "12/25" {
		t.Errorf("CardData.ExpiryDate = %v", cd.ExpiryDate)
	}
}

func TestMetadata(t *testing.T) {
	m := Metadata{
		Website:     "https://example.com",
		Description: "Test description",
		Tags:        []string{"tag1", "tag2"},
		Custom:      map[string]string{"key": "value"},
	}

	if m.Website != "https://example.com" {
		t.Errorf("Metadata.Website = %v", m.Website)
	}
	if len(m.Tags) != 2 {
		t.Errorf("Metadata.Tags length = %v, want 2", len(m.Tags))
	}
	if m.Custom["key"] != "value" {
		t.Errorf("Metadata.Custom[key] = %v", m.Custom["key"])
	}
}

func TestSyncData(t *testing.T) {
	now := time.Now()
	sd := SyncData{
		Secrets: []Secret{
			{ID: "1", Name: "Secret1"},
			{ID: "2", Name: "Secret2"},
		},
		LastSyncTime:  now,
		ClientVersion: "1.0.0",
	}

	if len(sd.Secrets) != 2 {
		t.Errorf("SyncData.Secrets length = %v, want 2", len(sd.Secrets))
	}
	if sd.ClientVersion != "1.0.0" {
		t.Errorf("SyncData.ClientVersion = %v", sd.ClientVersion)
	}
}

func TestSyncResponse(t *testing.T) {
	now := time.Now()
	sr := SyncResponse{
		UpdatedSecrets: []Secret{{ID: "1"}},
		DeletedIDs:     []string{"2", "3"},
		ServerTime:     now,
		HasConflicts:   false,
	}

	if len(sr.UpdatedSecrets) != 1 {
		t.Errorf("SyncResponse.UpdatedSecrets length = %v", len(sr.UpdatedSecrets))
	}
	if len(sr.DeletedIDs) != 2 {
		t.Errorf("SyncResponse.DeletedIDs length = %v", len(sr.DeletedIDs))
	}
	if sr.HasConflicts {
		t.Error("SyncResponse.HasConflicts should be false")
	}
}

func TestAuthRequest(t *testing.T) {
	ar := AuthRequest{
		Login:    "user",
		Password: "pass",
	}

	if ar.Login != "user" {
		t.Errorf("AuthRequest.Login = %v", ar.Login)
	}
}

func TestAuthResponse(t *testing.T) {
	now := time.Now()
	ar := AuthResponse{
		Token:     "jwt-token",
		ExpiresAt: now.Add(24 * time.Hour),
		UserID:    1,
	}

	if ar.Token != "jwt-token" {
		t.Errorf("AuthResponse.Token = %v", ar.Token)
	}
	if ar.UserID != 1 {
		t.Errorf("AuthResponse.UserID = %v", ar.UserID)
	}
}

func TestRegisterRequest(t *testing.T) {
	rr := RegisterRequest{
		Login:    "newuser",
		Password: "newpass",
	}

	if rr.Login != "newuser" {
		t.Errorf("RegisterRequest.Login = %v", rr.Login)
	}
}

func TestRegisterResponse(t *testing.T) {
	rr := RegisterResponse{
		UserID: 42,
		Token:  "new-token",
	}

	if rr.UserID != 42 {
		t.Errorf("RegisterResponse.UserID = %v", rr.UserID)
	}
}
