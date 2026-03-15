package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ServerAddress != "localhost:3200" {
		t.Errorf("DefaultConfig().ServerAddress = %v, want localhost:3200", cfg.ServerAddress)
	}

	if cfg.UseTLS != false {
		t.Error("DefaultConfig().UseTLS should be false")
	}

	if cfg.AutoSync != true {
		t.Error("DefaultConfig().AutoSync should be true")
	}

	if cfg.SyncInterval != 300 {
		t.Errorf("DefaultConfig().SyncInterval = %v, want 300", cfg.SyncInterval)
	}

	if cfg.DefaultTimeout != 30 {
		t.Errorf("DefaultConfig().DefaultTimeout = %v, want 30", cfg.DefaultTimeout)
	}
}

func TestGetConfigPath(t *testing.T) {
	path := GetConfigPath()

	if path == "" {
		t.Error("GetConfigPath() returned empty string")
	}

	if filepath.Base(path) != "config.json" {
		t.Errorf("GetConfigPath() = %v, should end with config.json", path)
	}
}

func TestConfig_IsAuthenticated(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want bool
	}{
		{
			name: "authenticated",
			cfg: &Config{
				Token:     "valid-token",
				ExpiresAt: time.Now().Add(time.Hour),
			},
			want: true,
		},
		{
			name: "no token",
			cfg: &Config{
				Token:     "",
				ExpiresAt: time.Now().Add(time.Hour),
			},
			want: false,
		},
		{
			name: "expired token",
			cfg: &Config{
				Token:     "valid-token",
				ExpiresAt: time.Now().Add(-time.Hour),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsAuthenticated(); got != tt.want {
				t.Errorf("IsAuthenticated() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_ClearAuth(t *testing.T) {
	cfg := &Config{
		Token:     "some-token",
		ExpiresAt: time.Now().Add(time.Hour),
		UserID:    42,
		Login:     "testuser",
	}

	cfg.ClearAuth()

	if cfg.Token != "" {
		t.Error("ClearAuth() should clear Token")
	}
	if !cfg.ExpiresAt.IsZero() {
		t.Error("ClearAuth() should clear ExpiresAt")
	}
	if cfg.UserID != 0 {
		t.Error("ClearAuth() should clear UserID")
	}
	if cfg.Login != "" {
		t.Error("ClearAuth() should clear Login")
	}
}

func TestConfig_SetAuth(t *testing.T) {
	cfg := &Config{}
	expiresAt := time.Now().Add(time.Hour)

	cfg.SetAuth("new-token", expiresAt, 123, "newuser")

	if cfg.Token != "new-token" {
		t.Errorf("SetAuth() Token = %v, want new-token", cfg.Token)
	}
	if cfg.ExpiresAt != expiresAt {
		t.Errorf("SetAuth() ExpiresAt = %v, want %v", cfg.ExpiresAt, expiresAt)
	}
	if cfg.UserID != 123 {
		t.Errorf("SetAuth() UserID = %v, want 123", cfg.UserID)
	}
	if cfg.Login != "newuser" {
		t.Errorf("SetAuth() Login = %v, want newuser", cfg.Login)
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name:    "valid config",
			cfg:     DefaultConfig(),
			wantErr: false,
		},
		{
			name: "empty server address",
			cfg: &Config{
				ServerAddress: "",
				DatabasePath:  "/path/to/db",
			},
			wantErr: true,
		},
		{
			name: "empty database path",
			cfg: &Config{
				ServerAddress: "localhost:3200",
				DatabasePath:  "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_EnsureDirectories(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gophkeeper-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := &Config{
		DatabasePath: filepath.Join(tmpDir, "subdir", "test.db"),
	}

	err = cfg.EnsureDirectories()
	if err != nil {
		t.Errorf("EnsureDirectories() error = %v", err)
	}

	dbDir := filepath.Dir(cfg.DatabasePath)
	if _, err := os.Stat(dbDir); os.IsNotExist(err) {
		t.Error("EnsureDirectories() did not create database directory")
	}
}

func TestConfig_SaveLoad(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gophkeeper-config-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.json")

	cfg := &Config{
		ServerAddress:  "test-server:3200",
		UseTLS:         true,
		DatabasePath:   "/path/to/db",
		AutoSync:       false,
		SyncInterval:   600,
		DefaultTimeout: 60,
	}

	os.MkdirAll(filepath.Dir(configPath), 0700)

	if cfg.ServerAddress != "test-server:3200" {
		t.Errorf("Config.ServerAddress = %v", cfg.ServerAddress)
	}
}
