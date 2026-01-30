
package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/shuklarituparn/Gopherpass/internal/client/api"
	"github.com/shuklarituparn/Gopherpass/internal/client/config"
	"github.com/shuklarituparn/Gopherpass/internal/client/storage"
	"github.com/shuklarituparn/Gopherpass/internal/crypto"
)

var (
	BuildVersion = "dev"
	BuildDate    = "unknown"
	BuildCommit  = "unknown"
)

type App struct {
	Config      *config.Config
	APIClient   *api.Client
	Storage     *storage.LocalStorage
	Encryptor   *crypto.Encryptor
}

var app = &App{}

var rootCmd = &cobra.Command{
	Use:   "gophkeeper",
	Short: "GophKeeper - Secure password and secrets manager",
	Long: `GophKeeper is a client-server system for securely storing and managing
your passwords, text notes, binary files, and bank card information.

All data is encrypted on the client side before being sent to the server,
ensuring your secrets remain private.`,
	PersistentPreRunE: initApp,
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		cleanup()
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

	return nil
}

func cleanup() {
	if app.Storage != nil {
		app.Storage.Close()
	}
	if app.APIClient != nil {
		app.APIClient.Close()
	}
}

func requireAuth() error {
	if !app.Config.IsAuthenticated() {
		return fmt.Errorf("not logged in. Please run 'gophkeeper login' first")
	}
	return nil
}

func requireEncryptionKey() error {
	if app.Encryptor == nil {
		return fmt.Errorf("encryption key not set. Please run 'gophkeeper login' first")
	}
	return nil
}

func setEncryptionKey(masterPassword string) error {
	encryptor, err := crypto.NewEncryptor(masterPassword)
	if err != nil {
		return err
	}
	app.Encryptor = encryptor
	return nil
}
