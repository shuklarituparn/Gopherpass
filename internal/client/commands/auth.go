package commands

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new user account",
	Long: `Register creates a new user account on the GophKeeper server.
You will be prompted to enter a login and password.`,
	RunE: runRegister,
}

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to your account",
	Long: `Login authenticates you with the GophKeeper server and stores
the authentication token for subsequent operations.`,
	RunE: runLogin,
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout from your account",
	Long:  `Logout clears your authentication token and local session.`,
	RunE:  runLogout,
}

func init() {
	registerCmd.Flags().StringP("login", "l", "", "Login/username")
	registerCmd.Flags().StringP("password", "p", "", "Password")

	loginCmd.Flags().StringP("login", "l", "", "Login/username")
	loginCmd.Flags().StringP("password", "p", "", "Password")
}

func runRegister(cmd *cobra.Command, args []string) error {
	app := getApp(cmd)
	if app == nil {
		return fmt.Errorf("application not initialized")
	}

	login, _ := cmd.Flags().GetString("login")
	password, _ := cmd.Flags().GetString("password")

	if login == "" {
		fmt.Print("Enter login: ")
		reader := bufio.NewReader(os.Stdin)
		var err error
		login, err = reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read login: %w", err)
		}
		login = strings.TrimSpace(login)
	}

	if password == "" {
		fmt.Print("Enter password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println()
		password = string(bytePassword)

		fmt.Print("Confirm password: ")
		byteConfirm, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read password confirmation: %w", err)
		}
		fmt.Println()

		if password != string(byteConfirm) {
			return fmt.Errorf("passwords do not match")
		}
	}

	resp, err := app.APIClient.Register(login, password)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	app.Config.SetAuth(resp.Token, app.Config.ExpiresAt, resp.UserID, login)
	if err := app.Config.Save(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	if err := setEncryptionKey(cmd, password); err != nil {
		return fmt.Errorf("failed to set encryption key: %w", err)
	}

	fmt.Printf("Successfully registered as '%s'\n", login)
	return nil
}

func runLogin(cmd *cobra.Command, args []string) error {
	app := getApp(cmd)
	if app == nil {
		return fmt.Errorf("application not initialized")
	}

	login, _ := cmd.Flags().GetString("login")
	password, _ := cmd.Flags().GetString("password")

	if login == "" {
		fmt.Print("Enter login: ")
		reader := bufio.NewReader(os.Stdin)
		var err error
		login, err = reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read login: %w", err)
		}
		login = strings.TrimSpace(login)
	}

	if password == "" {
		fmt.Print("Enter password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println()
		password = string(bytePassword)
	}

	resp, err := app.APIClient.Login(login, password)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	app.Config.SetAuth(resp.Token, resp.ExpiresAt, resp.UserID, login)
	if err := app.Config.Save(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	if err := setEncryptionKey(cmd, password); err != nil {
		return fmt.Errorf("failed to set encryption key: %w", err)
	}

	fmt.Printf("Successfully logged in as '%s'\n", login)
	fmt.Printf("Session expires at: %s\n", resp.ExpiresAt.Format("2006-01-02 15:04:05"))
	return nil
}

func runLogout(cmd *cobra.Command, args []string) error {
	app := getApp(cmd)
	if app == nil {
		return fmt.Errorf("application not initialized")
	}

	if !app.Config.IsAuthenticated() {
		fmt.Println("Not logged in")
		return nil
	}

	login := app.Config.Login
	app.Config.ClearAuth()
	if err := app.Config.Save(); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	app.Encryptor = nil

	fmt.Printf("Successfully logged out from '%s'\n", login)
	return nil
}