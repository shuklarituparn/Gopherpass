package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	GRPCAddress  string
	HTTPAddress  string
	Environment  string

	DatabaseDSN string

	JWTSecret     string
	JWTExpiration time.Duration

	EnableTLS bool
	TLSCert   string
	TLSKey    string

	LogLevel string
}

func DefaultConfig() *Config {
	return &Config{
		GRPCAddress:   ":3200",
		HTTPAddress:   ":8080",
		Environment:   "development",
		DatabaseDSN:   "postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable",
		JWTSecret:     "default-secret-change-in-production",
		JWTExpiration: 24 * time.Hour,
		EnableTLS:     false,
		LogLevel:      "info",
	}
}

func Load() *Config {
	cfg := DefaultConfig()

	if val := os.Getenv("GRPC_ADDRESS"); val != "" {
		cfg.GRPCAddress = val
	}
	if val := os.Getenv("HTTP_ADDRESS"); val != "" {
		cfg.HTTPAddress = val
	}
	if val := os.Getenv("ENVIRONMENT"); val != "" {
		cfg.Environment = val
	}
	if val := os.Getenv("DATABASE_DSN"); val != "" {
		cfg.DatabaseDSN = val
	}
	if val := os.Getenv("JWT_SECRET"); val != "" {
		cfg.JWTSecret = val
	}
	if val := os.Getenv("JWT_EXPIRATION"); val != "" {
		if duration, err := time.ParseDuration(val); err == nil {
			cfg.JWTExpiration = duration
		}
	}
	if val := os.Getenv("ENABLE_TLS"); val != "" {
		cfg.EnableTLS = val == "true" || val == "1"
	}
	if val := os.Getenv("TLS_CERT"); val != "" {
		cfg.TLSCert = val
	}
	if val := os.Getenv("TLS_KEY"); val != "" {
		cfg.TLSKey = val
	}
	if val := os.Getenv("LOG_LEVEL"); val != "" {
		cfg.LogLevel = val
	}

	return cfg
}

func (c *Config) Validate() []error {
	var errs []error

	if c.GRPCAddress == "" {
		errs = append(errs, &configError{field: "GRPCAddress", message: "cannot be empty"})
	}
	if c.DatabaseDSN == "" {
		errs = append(errs, &configError{field: "DatabaseDSN", message: "cannot be empty"})
	}
	if c.JWTSecret == "" {
		errs = append(errs, &configError{field: "JWTSecret", message: "cannot be empty"})
	}
	if c.Environment == "production" && c.JWTSecret == "default-secret-change-in-production" {
		errs = append(errs, &configError{field: "JWTSecret", message: "must be changed in production"})
	}
	if c.EnableTLS && (c.TLSCert == "" || c.TLSKey == "") {
		errs = append(errs, &configError{field: "TLS", message: "TLS is enabled but cert or key is missing"})
	}

	return errs
}

type configError struct {
	field   string
	message string
}

func (e *configError) Error() string {
	return "config error: " + e.field + " " + e.message
}

func GetEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if intVal, err := strconv.Atoi(val); err == nil {
			return intVal
		}
	}
	return defaultVal
}

func GetEnvBool(key string, defaultVal bool) bool {
	if val := os.Getenv(key); val != "" {
		return val == "true" || val == "1"
	}
	return defaultVal
}
