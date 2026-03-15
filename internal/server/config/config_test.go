package config

import (
	"os"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.GRPCAddress != ":3200" {
		t.Errorf("DefaultConfig().GRPCAddress = %v, want :3200", cfg.GRPCAddress)
	}

	if cfg.HTTPAddress != ":8080" {
		t.Errorf("DefaultConfig().HTTPAddress = %v, want :8080", cfg.HTTPAddress)
	}

	if cfg.Environment != "development" {
		t.Errorf("DefaultConfig().Environment = %v, want development", cfg.Environment)
	}

	if cfg.JWTExpiration != 24*time.Hour {
		t.Errorf("DefaultConfig().JWTExpiration = %v, want 24h", cfg.JWTExpiration)
	}

	if cfg.EnableTLS != false {
		t.Error("DefaultConfig().EnableTLS should be false")
	}

	if cfg.LogLevel != "info" {
		t.Errorf("DefaultConfig().LogLevel = %v, want info", cfg.LogLevel)
	}
}

func TestLoad(t *testing.T) {
	envVars := []string{
		"GRPC_ADDRESS", "HTTP_ADDRESS", "ENVIRONMENT",
		"DATABASE_DSN", "JWT_SECRET", "JWT_EXPIRATION",
		"ENABLE_TLS", "TLS_CERT", "TLS_KEY", "LOG_LEVEL",
	}
	for _, v := range envVars {
		os.Unsetenv(v)
	}

	cfg := Load()
	if cfg == nil {
		t.Fatal("Load() returned nil")
	}

	if cfg.GRPCAddress != ":3200" {
		t.Errorf("Load().GRPCAddress = %v, want :3200", cfg.GRPCAddress)
	}
}

func TestLoad_WithEnvVars(t *testing.T) {
	os.Setenv("GRPC_ADDRESS", ":4000")
	os.Setenv("HTTP_ADDRESS", ":9000")
	os.Setenv("ENVIRONMENT", "production")
	os.Setenv("DATABASE_DSN", "postgres://test:test@localhost/test")
	os.Setenv("JWT_SECRET", "test-secret")
	os.Setenv("JWT_EXPIRATION", "12h")
	os.Setenv("ENABLE_TLS", "true")
	os.Setenv("TLS_CERT", "/path/to/cert")
	os.Setenv("TLS_KEY", "/path/to/key")
	os.Setenv("LOG_LEVEL", "debug")

	defer func() {
		os.Unsetenv("GRPC_ADDRESS")
		os.Unsetenv("HTTP_ADDRESS")
		os.Unsetenv("ENVIRONMENT")
		os.Unsetenv("DATABASE_DSN")
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("JWT_EXPIRATION")
		os.Unsetenv("ENABLE_TLS")
		os.Unsetenv("TLS_CERT")
		os.Unsetenv("TLS_KEY")
		os.Unsetenv("LOG_LEVEL")
	}()

	cfg := Load()

	if cfg.GRPCAddress != ":4000" {
		t.Errorf("Load().GRPCAddress = %v, want :4000", cfg.GRPCAddress)
	}

	if cfg.HTTPAddress != ":9000" {
		t.Errorf("Load().HTTPAddress = %v, want :9000", cfg.HTTPAddress)
	}

	if cfg.Environment != "production" {
		t.Errorf("Load().Environment = %v, want production", cfg.Environment)
	}

	if cfg.DatabaseDSN != "postgres://test:test@localhost/test" {
		t.Errorf("Load().DatabaseDSN = %v", cfg.DatabaseDSN)
	}

	if cfg.JWTSecret != "test-secret" {
		t.Errorf("Load().JWTSecret = %v", cfg.JWTSecret)
	}

	if cfg.JWTExpiration != 12*time.Hour {
		t.Errorf("Load().JWTExpiration = %v, want 12h", cfg.JWTExpiration)
	}

	if !cfg.EnableTLS {
		t.Error("Load().EnableTLS should be true")
	}

	if cfg.TLSCert != "/path/to/cert" {
		t.Errorf("Load().TLSCert = %v", cfg.TLSCert)
	}

	if cfg.TLSKey != "/path/to/key" {
		t.Errorf("Load().TLSKey = %v", cfg.TLSKey)
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("Load().LogLevel = %v", cfg.LogLevel)
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		cfg       *Config
		wantErrs  int
	}{
		{
			name:     "valid config",
			cfg:      DefaultConfig(),
			wantErrs: 0,
		},
		{
			name: "empty GRPC address",
			cfg: &Config{
				GRPCAddress: "",
				DatabaseDSN: "postgres://...",
				JWTSecret:   "secret",
			},
			wantErrs: 1,
		},
		{
			name: "empty database DSN",
			cfg: &Config{
				GRPCAddress: ":3200",
				DatabaseDSN: "",
				JWTSecret:   "secret",
			},
			wantErrs: 1,
		},
		{
			name: "empty JWT secret",
			cfg: &Config{
				GRPCAddress: ":3200",
				DatabaseDSN: "postgres://...",
				JWTSecret:   "",
			},
			wantErrs: 1,
		},
		{
			name: "production with default secret",
			cfg: &Config{
				GRPCAddress: ":3200",
				DatabaseDSN: "postgres://...",
				JWTSecret:   "default-secret-change-in-production",
				Environment: "production",
			},
			wantErrs: 1,
		},
		{
			name: "TLS enabled without cert",
			cfg: &Config{
				GRPCAddress: ":3200",
				DatabaseDSN: "postgres://...",
				JWTSecret:   "secret",
				EnableTLS:   true,
				TLSCert:     "",
				TLSKey:      "/path/to/key",
			},
			wantErrs: 1,
		},
		{
			name: "TLS enabled without key",
			cfg: &Config{
				GRPCAddress: ":3200",
				DatabaseDSN: "postgres://...",
				JWTSecret:   "secret",
				EnableTLS:   true,
				TLSCert:     "/path/to/cert",
				TLSKey:      "",
			},
			wantErrs: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := tt.cfg.Validate()
			if len(errs) != tt.wantErrs {
				t.Errorf("Validate() returned %d errors, want %d: %v", len(errs), tt.wantErrs, errs)
			}
		})
	}
}

func TestGetEnvInt(t *testing.T) {
	os.Unsetenv("TEST_INT")
	result := GetEnvInt("TEST_INT", 42)
	if result != 42 {
		t.Errorf("GetEnvInt() = %d, want 42", result)
	}

	os.Setenv("TEST_INT", "100")
	defer os.Unsetenv("TEST_INT")
	result = GetEnvInt("TEST_INT", 42)
	if result != 100 {
		t.Errorf("GetEnvInt() = %d, want 100", result)
	}

	os.Setenv("TEST_INT", "not-a-number")
	result = GetEnvInt("TEST_INT", 42)
	if result != 42 {
		t.Errorf("GetEnvInt() = %d, want 42 (default)", result)
	}
}

func TestGetEnvBool(t *testing.T) {
	os.Unsetenv("TEST_BOOL")
	result := GetEnvBool("TEST_BOOL", true)
	if !result {
		t.Error("GetEnvBool() = false, want true")
	}

	os.Setenv("TEST_BOOL", "true")
	defer os.Unsetenv("TEST_BOOL")
	result = GetEnvBool("TEST_BOOL", false)
	if !result {
		t.Error("GetEnvBool() = false, want true")
	}

	os.Setenv("TEST_BOOL", "1")
	result = GetEnvBool("TEST_BOOL", false)
	if !result {
		t.Error("GetEnvBool() = false, want true")
	}

	os.Setenv("TEST_BOOL", "false")
	result = GetEnvBool("TEST_BOOL", true)
	if result {
		t.Error("GetEnvBool() = true, want false")
	}
}

func TestConfigError_Error(t *testing.T) {
	err := &configError{
		field:   "TestField",
		message: "test message",
	}

	expected := "config error: TestField test message"
	if err.Error() != expected {
		t.Errorf("configError.Error() = %q, want %q", err.Error(), expected)
	}
}
