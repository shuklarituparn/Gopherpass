package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	ServerAddress string `json:"server_address"`
	UseTLS        bool   `json:"use_tls"`
	TLSCertFile   string `json:"tls_cert_file,omitempty"`

	Token     string    `json:"token,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	UserID    int64     `json:"user_id,omitempty"`
	Login     string    `json:"login,omitempty"`

	DatabasePath  string `json:"database_path"`
	EncryptionKey string `json:"-"` 

	LastSyncTime time.Time `json:"last_sync_time,omitempty"`
	AutoSync     bool      `json:"auto_sync"`
	SyncInterval int       `json:"sync_interval"` 

	DefaultTimeout int `json:"default_timeout"` 
}

func DefaultConfig() *Config {
	return &Config{
		ServerAddress:  "localhost:3200",
		UseTLS:         false,
		DatabasePath:   getDefaultDBPath(),
		AutoSync:       true,
		SyncInterval:   300, 
		DefaultTimeout: 30,
	}
}

func getDefaultDBPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "gophkeeper.db"
	}
	configDir := filepath.Join(homeDir, ".gophkeeper")
	return filepath.Join(configDir, "data.db")
}

func GetConfigPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "gophkeeper.json"
	}
	return filepath.Join(homeDir, ".gophkeeper", "config.json")
}


func Load() (*Config, error) {
	configPath := GetConfigPath()

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, err
	}

	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) Save() error {
	configPath := GetConfigPath()

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0600)
}

func (c *Config) IsAuthenticated() bool {
	return c.Token != "" && time.Now().Before(c.ExpiresAt)
}

func (c *Config) ClearAuth() {
	c.Token = ""
	c.ExpiresAt = time.Time{}
	c.UserID = 0
	c.Login = ""
}

func (c *Config) SetAuth(token string, expiresAt time.Time, userID int64, login string) {
	c.Token = token
	c.ExpiresAt = expiresAt
	c.UserID = userID
	c.Login = login
}

func (c *Config) Validate() error {
	if c.ServerAddress == "" {
		return errors.New("server address is required")
	}
	if c.DatabasePath == "" {
		return errors.New("database path is required")
	}
	return nil
}

func (c *Config) EnsureDirectories() error {
	dbDir := filepath.Dir(c.DatabasePath)
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		return err
	}

	configDir := filepath.Dir(GetConfigPath())
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	return nil
}
