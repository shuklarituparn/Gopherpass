package commands

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/shuklarituparn/Gopherpass/internal/client/api"
	"github.com/shuklarituparn/Gopherpass/internal/client/config"
	"github.com/shuklarituparn/Gopherpass/internal/client/storage"
	"github.com/shuklarituparn/Gopherpass/internal/crypto"
	"github.com/shuklarituparn/Gopherpass/internal/models"
)

var (
	BuildVersion = "dev"
	BuildDate    = "unknown"
	BuildCommit  = "unknown"
)

type appContextKey struct{}

type ConfigProvider interface {
	IsAuthenticated() bool
	SetAuth(token string, expiresAt time.Time, userID int64, login string)
	ClearAuth()
	Save() error
	EnsureDirectories() error
}

type APIClientProvider interface {
	SetToken(token string)
	Register(login, password string) (*models.RegisterResponse, error)
	Login(login, password string) (*models.AuthResponse, error)
	Sync(lastSyncTime time.Time, localChanges []models.Secret) (*models.SyncResponse, error)
	Close() error
}

type StorageProvider interface {
	CreateSecret(secret *models.Secret) error
	GetSecret(id string) (*models.Secret, error)
	GetAllSecrets() ([]models.Secret, error)
	GetSecretsByType(dataType models.DataType) ([]models.Secret, error)
	DeleteSecret(id string) error
	UpsertSecret(secret *models.Secret) error
	DeleteSecretPermanently(id string) error
	MarkAsSynced(id string) error
	GetLocallyModifiedSecrets() ([]models.Secret, error)
	GetLastSyncTime() (time.Time, error)
	SetLastSyncTime(t time.Time) error
	Close() error
}

type EncryptorProvider interface {
	EncryptBytes(plaintext []byte) ([]byte, error)
	DecryptBytes(ciphertext []byte) ([]byte, error)
}

type App struct {
	Config    *config.Config
	APIClient *api.Client
	Storage   *storage.LocalStorage
	Encryptor *crypto.Encryptor
}

func (a *App) GetConfig() *config.Config {
	return a.Config
}

func (a *App) GetAPIClient() *api.Client {
	return a.APIClient
}

func (a *App) GetStorage() *storage.LocalStorage {
	return a.Storage
}

func (a *App) GetEncryptor() *crypto.Encryptor {
	return a.Encryptor
}

func (a *App) SetEncryptor(e *crypto.Encryptor) {
	a.Encryptor = e
}

func getApp(cmd *cobra.Command) *App {
	ctx := cmd.Context()
	if ctx == nil {
		return nil
	}
	app, _ := ctx.Value(appContextKey{}).(*App)
	return app
}

func setApp(cmd *cobra.Command, app *App) {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	cmd.SetContext(context.WithValue(ctx, appContextKey{}, app))
}

var rootCmd = &cobra.Command{
	Use:   "gophkeeper",
	Short: "GophKeeper - Secure password and secrets manager",
	Long: `GophKeeper is a client-server system for securely storing and managing
your passwords, text notes, binary files, and bank card information.

All data is encrypted on the client side before being sent to the server,
ensuring your secrets remain private.`,
	PersistentPreRunE: initApp,
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		cleanup(cmd)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringP("server", "s", "", "Server address (overrides config)")
	rootCmd.PersistentFlags().BoolP("tls", "t", false, "Use TLS for connection")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(registerCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
	rootCmd.AddCommand(syncCmd)
	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(configCmd)
}

func initApp(cmd *cobra.Command, args []string) error {
	if cmd.Name() == "version" {
		return nil
	}

	app := &App{}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	app.Config = cfg

	if server, _ := cmd.Flags().GetString("server"); server != "" {
		cfg.ServerAddress = server
	}
	if tls, _ := cmd.Flags().GetBool("tls"); tls {
		cfg.UseTLS = true
	}

	if err := cfg.EnsureDirectories(); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	localStorage, err := storage.NewLocalStorage(cfg.DatabasePath)
	if err != nil {
		return fmt.Errorf("failed to initialize local storage: %w", err)
	}
	app.Storage = localStorage

	clientOpts := &api.ClientOptions{
		Address:     cfg.ServerAddress,
		UseTLS:      cfg.UseTLS,
		TLSCertFile: cfg.TLSCertFile,
	}
	apiClient, err := api.NewClient(clientOpts)
	if err != nil {
		return fmt.Errorf("failed to create API client: %w", err)
	}
	app.APIClient = apiClient

	if cfg.IsAuthenticated() {
		apiClient.SetToken(cfg.Token)
	}

	setApp(cmd, app)

	return nil
}

func cleanup(cmd *cobra.Command) {
	app := getApp(cmd)
	if app == nil {
		return
	}
	if app.Storage != nil {
		app.Storage.Close()
	}
	if app.APIClient != nil {
		app.APIClient.Close()
	}
}

func requireAuth(cmd *cobra.Command) error {
	app := getApp(cmd)
	if app == nil {
		return fmt.Errorf("application not initialized")
	}
	if !app.Config.IsAuthenticated() {
		return fmt.Errorf("not logged in. Please run 'gophkeeper login' first")
	}
	return nil
}

func requireEncryptionKey(cmd *cobra.Command) error {
	app := getApp(cmd)
	if app == nil {
		return fmt.Errorf("application not initialized")
	}
	if app.Encryptor == nil {
		return fmt.Errorf("encryption key not set. Please run 'gophkeeper login' first")
	}
	return nil
}

func setEncryptionKey(cmd *cobra.Command, masterPassword string) error {
	app := getApp(cmd)
	if app == nil {
		return fmt.Errorf("application not initialized")
	}
	encryptor, err := crypto.NewEncryptor(masterPassword)
	if err != nil {
		return err
	}
	app.Encryptor = encryptor
	return nil
}