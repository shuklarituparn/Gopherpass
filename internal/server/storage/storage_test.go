package storage

import (
	"context"
	"testing"
)

func TestContainsString(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		want   bool
	}{
		{"hello world", "world", true},
		{"hello world", "hello", true},
		{"hello", "hello", true},
		{"hello", "world", false},
		{"", "", true},
		{"hello", "", true},
		{"", "hello", false},
		{"duplicate key", "duplicate key", true},
		{"error 23505", "23505", true},
		{"unique constraint violation", "unique constraint", true},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			got := containsString(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("containsString(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

func TestContainsSubstring(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		want   bool
	}{
		{"hello world", "world", true},
		{"hello world", "hello", true},
		{"hello world", "lo wo", true},
		{"hello", "hello", true},
		{"hello", "world", false},
		{"abc", "abcd", false},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			got := containsSubstring(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("containsSubstring(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

func TestIsUniqueViolation(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"23505 error", &testError{"pq: error code 23505"}, true},
		{"unique constraint error", &testError{"unique constraint violation"}, true},
		{"duplicate key error", &testError{"duplicate key value"}, true},
		{"other error", &testError{"some other error"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUniqueViolation(tt.err)
			if got != tt.want {
				t.Errorf("isUniqueViolation() = %v, want %v", got, tt.want)
			}
		})
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}

func TestStorageErrors(t *testing.T) {
	if ErrUserNotFound.Error() != "user not found" {
		t.Errorf("ErrUserNotFound = %v", ErrUserNotFound)
	}
	if ErrUserExists.Error() != "user already exists" {
		t.Errorf("ErrUserExists = %v", ErrUserExists)
	}
	if ErrSecretNotFound.Error() != "secret not found" {
		t.Errorf("ErrSecretNotFound = %v", ErrSecretNotFound)
	}
	if ErrVersionConflict.Error() != "version conflict" {
		t.Errorf("ErrVersionConflict = %v", ErrVersionConflict)
	}
	if ErrDatabaseError.Error() != "database error" {
		t.Errorf("ErrDatabaseError = %v", ErrDatabaseError)
	}
}

func TestNewPostgresStorage_InvalidDSN(t *testing.T) {
	_, err := NewPostgresStorage("invalid-dsn")
	if err == nil {
		t.Error("NewPostgresStorage() should fail with invalid DSN")
	}
}



func TestPostgresStorage_Ping(t *testing.T) {
	t.Skip("Requires database connection")

	storage, err := NewPostgresStorage("postgres://test:test@localhost/test?sslmode=disable")
	if err != nil {
		t.Skipf("Could not connect to database: %v", err)
	}
	defer storage.Close()

	ctx := context.Background()
	if err := storage.Ping(ctx); err != nil {
		t.Errorf("Ping() error = %v", err)
	}
}
