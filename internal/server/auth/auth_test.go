package auth

import (
	"context"
	"testing"
	"time"
)

func TestNewTokenManager(t *testing.T) {
	tm := NewTokenManager("secret", 24*time.Hour)
	if tm == nil {
		t.Error("NewTokenManager() returned nil")
	}
}

func TestTokenManager_GenerateToken(t *testing.T) {
	tm := NewTokenManager("test-secret", time.Hour)

	token, expiresAt, err := tm.GenerateToken(1, "testuser")
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	if token == "" {
		t.Error("GenerateToken() returned empty token")
	}

	if expiresAt.Before(time.Now()) {
		t.Error("GenerateToken() returned expired token")
	}

	expectedExpiry := time.Now().Add(time.Hour)
	if expiresAt.Before(expectedExpiry.Add(-time.Minute)) || expiresAt.After(expectedExpiry.Add(time.Minute)) {
		t.Error("GenerateToken() expiry time is not within expected range")
	}
}

func TestTokenManager_ValidateToken(t *testing.T) {
	tm := NewTokenManager("test-secret", time.Hour)

	token, _, err := tm.GenerateToken(42, "john")
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	claims, err := tm.ValidateToken(token)
	if err != nil {
		t.Errorf("ValidateToken() error = %v", err)
	}

	if claims.UserID != 42 {
		t.Errorf("ValidateToken() UserID = %v, want 42", claims.UserID)
	}

	if claims.Login != "john" {
		t.Errorf("ValidateToken() Login = %v, want john", claims.Login)
	}
}

func TestTokenManager_ValidateInvalidToken(t *testing.T) {
	tm := NewTokenManager("test-secret", time.Hour)

	tests := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"invalid format", "not.a.valid.token"},
		{"random string", "randomstring"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tm.ValidateToken(tt.token)
			if err == nil {
				t.Error("ValidateToken() expected error for invalid token")
			}
		})
	}
}

func TestTokenManager_ValidateExpiredToken(t *testing.T) {
	tm := NewTokenManager("test-secret", -time.Hour) 

	token, _, err := tm.GenerateToken(1, "user")
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	_, err = tm.ValidateToken(token)
	if err != ErrExpiredToken {
		t.Errorf("ValidateToken() error = %v, want ErrExpiredToken", err)
	}
}

func TestTokenManager_ValidateWrongSecret(t *testing.T) {
	tm1 := NewTokenManager("secret1", time.Hour)
	tm2 := NewTokenManager("secret2", time.Hour)

	token, _, err := tm1.GenerateToken(1, "user")
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	_, err = tm2.ValidateToken(token)
	if err == nil {
		t.Error("ValidateToken() should fail with wrong secret")
	}
}

func TestTokenManager_RefreshToken(t *testing.T) {
	tm := NewTokenManager("test-secret", time.Hour)

	originalToken, _, err := tm.GenerateToken(1, "user")
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	
	time.Sleep(time.Millisecond * 10)

	newToken, newExpiry, err := tm.RefreshToken(originalToken)
	if err != nil {
		t.Errorf("RefreshToken() error = %v", err)
	}

	if newToken == "" {
		t.Error("RefreshToken() returned empty token")
	}


	if newExpiry.Before(time.Now()) {
		t.Error("RefreshToken() returned expired token")
	}

	claims, err := tm.ValidateToken(newToken)
	if err != nil {
		t.Errorf("ValidateToken() error = %v for refreshed token", err)
	}

	if claims.UserID != 1 {
		t.Errorf("RefreshToken() UserID changed, got %v want 1", claims.UserID)
	}
}

func TestGetUserIDFromContext(t *testing.T) {
	ctx := context.Background()
	_, ok := GetUserIDFromContext(ctx)
	if ok {
		t.Error("GetUserIDFromContext() should return false for context without user ID")
	}

	ctx = context.WithValue(ctx, UserIDKey, int64(42))
	userID, ok := GetUserIDFromContext(ctx)
	if !ok {
		t.Error("GetUserIDFromContext() should return true for context with user ID")
	}
	if userID != 42 {
		t.Errorf("GetUserIDFromContext() = %v, want 42", userID)
	}
}

func TestGetLoginFromContext(t *testing.T) {
	ctx := context.Background()
	_, ok := GetLoginFromContext(ctx)
	if ok {
		t.Error("GetLoginFromContext() should return false for context without login")
	}

	ctx = context.WithValue(ctx, LoginKey, "testuser")
	login, ok := GetLoginFromContext(ctx)
	if !ok {
		t.Error("GetLoginFromContext() should return true for context with login")
	}
	if login != "testuser" {
		t.Errorf("GetLoginFromContext() = %v, want testuser", login)
	}
}

func TestClaims(t *testing.T) {
	tm := NewTokenManager("test-secret", time.Hour)

	token, _, _ := tm.GenerateToken(123, "testlogin")
	claims, _ := tm.ValidateToken(token)

	if claims.Issuer != "gophkeeper" {
		t.Errorf("Claims.Issuer = %v, want gophkeeper", claims.Issuer)
	}

	if claims.UserID != 123 {
		t.Errorf("Claims.UserID = %v, want 123", claims.UserID)
	}

	if claims.Login != "testlogin" {
		t.Errorf("Claims.Login = %v, want testlogin", claims.Login)
	}
}

func BenchmarkGenerateToken(b *testing.B) {
	tm := NewTokenManager("benchmark-secret", time.Hour)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = tm.GenerateToken(1, "user")
	}
}

func BenchmarkValidateToken(b *testing.B) {
	tm := NewTokenManager("benchmark-secret", time.Hour)
	token, _, _ := tm.GenerateToken(1, "user")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = tm.ValidateToken(token)
	}
}

func TestWrappedStream_Context(t *testing.T) {
	ctx := context.WithValue(context.Background(), UserIDKey, int64(1))
	ws := &wrappedStream{ctx: ctx}

	if ws.Context() != ctx {
		t.Error("wrappedStream.Context() returned wrong context")
	}
}

func TestAuthErrors(t *testing.T) {
	if ErrInvalidToken.Error() != "invalid token" {
		t.Errorf("ErrInvalidToken = %v", ErrInvalidToken)
	}
	if ErrExpiredToken.Error() != "token has expired" {
		t.Errorf("ErrExpiredToken = %v", ErrExpiredToken)
	}
	if ErrMissingToken.Error() != "missing authorization token" {
		t.Errorf("ErrMissingToken = %v", ErrMissingToken)
	}
	if ErrInvalidClaims.Error() != "invalid token claims" {
		t.Errorf("ErrInvalidClaims = %v", ErrInvalidClaims)
	}
}

func TestContextKeys(t *testing.T) {
	if string(UserIDKey) != "user_id" {
		t.Errorf("UserIDKey = %v", UserIDKey)
	}
	if string(LoginKey) != "login" {
		t.Errorf("LoginKey = %v", LoginKey)
	}
}

func TestGetUserIDFromContext_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), UserIDKey, "not-an-int64")
	_, ok := GetUserIDFromContext(ctx)
	if ok {
		t.Error("GetUserIDFromContext() should return false for wrong type")
	}
}

func TestGetLoginFromContext_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), LoginKey, 123)
	_, ok := GetLoginFromContext(ctx)
	if ok {
		t.Error("GetLoginFromContext() should return false for wrong type")
	}
}
