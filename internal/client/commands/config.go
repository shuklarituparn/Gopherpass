package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/shuklarituparn/Gopherpass/internal/client/config"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage client configuration",
	Long:  `View and modify the GophKeeper client configuration.`,
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	RunE:  runConfigShow,
}

var configSetCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Set a configuration value",
	Args:  cobra.ExactArgs(2),
	RunE:  runConfigSet,
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Show configuration file path",
	Run:   runConfigPath,
}

func init() {
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configPathCmd)
}

func runConfigShow(cmd *cobra.Command, args []string) error {
	fmt.Println("GophKeeper Configuration:")
	fmt.Println()
	fmt.Printf("  Server Address:  %s\n", app.Config.ServerAddress)
	fmt.Printf("  Use TLS:         %t\n", app.Config.UseTLS)
	if app.Config.TLSCertFile != "" {
		fmt.Printf("  TLS Cert File:   %s\n", app.Config.TLSCertFile)
	}
	fmt.Printf("  Database Path:   %s\n", app.Config.DatabasePath)
	fmt.Printf("  Auto Sync:       %t\n", app.Config.AutoSync)
	fmt.Printf("  Sync Interval:   %d seconds\n", app.Config.SyncInterval)
	fmt.Printf("  Default Timeout: %d seconds\n", app.Config.DefaultTimeout)
	fmt.Println()
	fmt.Println("Authentication:")
	if app.Config.IsAuthenticated() {
		fmt.Printf("  Logged in as:    %s\n", app.Config.Login)
		fmt.Printf("  User ID:         %d\n", app.Config.UserID)
		fmt.Printf("  Session expires: %s\n", app.Config.ExpiresAt.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Println("  Not logged in")
	}
	if !app.Config.LastSyncTime.IsZero() {
		fmt.Printf("  Last sync:       %s\n", app.Config.LastSyncTime.Format("2006-01-02 15:04:05"))
	}

	return nil
}

func runConfigSet(cmd *cobra.Command, args []string) error {
	key := args[0]
	value := args[1]

	switch key {
	case "server":
		app.Config.ServerAddress = value
	case "tls":
		app.Config.UseTLS = value == "true" || value == "1"
	case "tls-cert":
		app.Config.TLSCertFile = value
	case "database":
		app.Config.DatabasePath = value
	case "auto-sync":
		app.Config.AutoSync = value == "true" || value == "1"
	case "sync-interval":
		var interval int
		if _, err := fmt.Sscanf(value, "%d", &interval); err != nil {
			return fmt.Errorf("invalid interval value: %s", value)
		}
		app.Config.SyncInterval = interval
	case "timeout":
		var timeout int
		if _, err := fmt.Sscanf(value, "%d", &timeout); err != nil {
			return fmt.Errorf("invalid timeout value: %s", value)
		}
		app.Config.DefaultTimeout = timeout
	default:
		return fmt.Errorf("unknown config key: %s\nValid keys: server, tls, tls-cert, database, auto-sync, sync-interval, timeout", key)
	}

	if err := app.Config.Save(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Configuration updated: %s = %s\n", key, value)
	return nil
}

func runConfigPath(cmd *cobra.Command, args []string) {
	fmt.Printf("Config file: %s\n", config.GetConfigPath())
	fmt.Printf("Database:    %s\n", app.Config.DatabasePath)
}
