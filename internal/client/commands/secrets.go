package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/shuklarituparn/Gopherpass/internal/models"
)

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new secret",
	Long:  `Add a new secret to your vault. Supports passwords, text notes, binary files, and bank cards.`,
}

var getCmd = &cobra.Command{
	Use:   "get [id]",
	Short: "Get a secret by ID",
	Long:  `Retrieve and display a specific secret by its ID.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runGet,
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all secrets",
	Long:  `List all secrets in your vault, optionally filtered by type.`,
	RunE:  runList,
}

var deleteCmd = &cobra.Command{
	Use:   "delete [id]",
	Short: "Delete a secret",
	Long:  `Delete a secret from your vault by its ID.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runDelete,
}

var addPasswordCmd = &cobra.Command{
	Use:   "password",
	Short: "Add a login/password pair",
	RunE:  runAddPassword,
}

var addTextCmd = &cobra.Command{
	Use:   "text",
	Short: "Add a text note",
	RunE:  runAddText,
}

var addCardCmd = &cobra.Command{
	Use:   "card",
	Short: "Add a bank card",
	RunE:  runAddCard,
}

var addFileCmd = &cobra.Command{
	Use:   "file [filepath]",
	Short: "Add a binary file",
	Args:  cobra.ExactArgs(1),
	RunE:  runAddFile,
}

func init() {
	addCmd.AddCommand(addPasswordCmd)
	addCmd.AddCommand(addTextCmd)
	addCmd.AddCommand(addCardCmd)
	addCmd.AddCommand(addFileCmd)

	addPasswordCmd.Flags().StringP("name", "n", "", "Name for this password entry")
	addPasswordCmd.Flags().StringP("login", "l", "", "Login/username")
	addPasswordCmd.Flags().StringP("password", "p", "", "Password")
	addPasswordCmd.Flags().StringP("url", "u", "", "Website URL")
	addPasswordCmd.Flags().StringP("notes", "", "", "Additional notes/metadata")

	addTextCmd.Flags().StringP("name", "n", "", "Name for this text entry")
	addTextCmd.Flags().StringP("text", "t", "", "Text content")
	addTextCmd.Flags().StringP("notes", "", "", "Additional notes/metadata")

	addCardCmd.Flags().StringP("name", "n", "", "Name for this card entry")
	addCardCmd.Flags().StringP("number", "", "", "Card number")
	addCardCmd.Flags().StringP("holder", "", "", "Card holder name")
	addCardCmd.Flags().StringP("expiry", "", "", "Expiry date (MM/YY)")
	addCardCmd.Flags().StringP("cvv", "", "", "CVV code")
	addCardCmd.Flags().StringP("notes", "", "", "Additional notes/metadata")

	addFileCmd.Flags().StringP("name", "n", "", "Name for this file entry")
	addFileCmd.Flags().StringP("notes", "", "", "Additional notes/metadata")

	listCmd.Flags().StringP("type", "t", "", "Filter by type (password, text, binary, card)")

	deleteCmd.Flags().BoolP("force", "f", false, "Skip confirmation")
}

func runAddPassword(cmd *cobra.Command, args []string) error {
	if err := requireAuth(cmd); err != nil {
		return err
	}
	if err := requireEncryptionKey(cmd); err != nil {
		return err
	}

	app := getApp(cmd)

	reader := bufio.NewReader(os.Stdin)

	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		fmt.Print("Enter name: ")
		name, _ = reader.ReadString('\n')
		name = strings.TrimSpace(name)
	}

	login, _ := cmd.Flags().GetString("login")
	if login == "" {
		fmt.Print("Enter login: ")
		login, _ = reader.ReadString('\n')
		login = strings.TrimSpace(login)
	}

	password, _ := cmd.Flags().GetString("password")
	if password == "" {
		fmt.Print("Enter password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println()
		password = string(bytePassword)
	}

	url, _ := cmd.Flags().GetString("url")
	notes, _ := cmd.Flags().GetString("notes")

	data := &models.LoginPassword{
		Login:    login,
		Password: password,
		URL:      url,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	encryptedData, err := app.Encryptor.EncryptBytes(jsonData)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	secret := &models.Secret{
		UserID:        app.Config.UserID,
		Name:          name,
		DataType:      models.DataTypeLoginPassword,
		EncryptedData: encryptedData,
		Metadata:      notes,
	}

	if err := app.Storage.CreateSecret(secret); err != nil {
		return fmt.Errorf("failed to save secret: %w", err)
	}

	fmt.Printf("Password '%s' added successfully (ID: %s)\n", name, secret.ID)
	return nil
}

func runAddText(cmd *cobra.Command, args []string) error {
	if err := requireAuth(cmd); err != nil {
		return err
	}
	if err := requireEncryptionKey(cmd); err != nil {
		return err
	}

	app := getApp(cmd)

	reader := bufio.NewReader(os.Stdin)

	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		fmt.Print("Enter name: ")
		name, _ = reader.ReadString('\n')
		name = strings.TrimSpace(name)
	}

	text, _ := cmd.Flags().GetString("text")
	if text == "" {
		fmt.Println("Enter text (end with Ctrl+D on empty line):")
		var lines []string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			lines = append(lines, line)
		}
		text = strings.Join(lines, "")
	}

	notes, _ := cmd.Flags().GetString("notes")

	data := &models.TextData{
		Text: text,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	encryptedData, err := app.Encryptor.EncryptBytes(jsonData)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	secret := &models.Secret{
		UserID:        app.Config.UserID,
		Name:          name,
		DataType:      models.DataTypeText,
		EncryptedData: encryptedData,
		Metadata:      notes,
	}

	if err := app.Storage.CreateSecret(secret); err != nil {
		return fmt.Errorf("failed to save secret: %w", err)
	}

	fmt.Printf("Text '%s' added successfully (ID: %s)\n", name, secret.ID)
	return nil
}

func runAddCard(cmd *cobra.Command, args []string) error {
	if err := requireAuth(cmd); err != nil {
		return err
	}
	if err := requireEncryptionKey(cmd); err != nil {
		return err
	}

	app := getApp(cmd)

	reader := bufio.NewReader(os.Stdin)

	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		fmt.Print("Enter name: ")
		name, _ = reader.ReadString('\n')
		name = strings.TrimSpace(name)
	}

	number, _ := cmd.Flags().GetString("number")
	if number == "" {
		fmt.Print("Enter card number: ")
		number, _ = reader.ReadString('\n')
		number = strings.TrimSpace(number)
	}

	holder, _ := cmd.Flags().GetString("holder")
	if holder == "" {
		fmt.Print("Enter card holder name: ")
		holder, _ = reader.ReadString('\n')
		holder = strings.TrimSpace(holder)
	}

	expiry, _ := cmd.Flags().GetString("expiry")
	if expiry == "" {
		fmt.Print("Enter expiry date (MM/YY): ")
		expiry, _ = reader.ReadString('\n')
		expiry = strings.TrimSpace(expiry)
	}

	cvv, _ := cmd.Flags().GetString("cvv")
	if cvv == "" {
		fmt.Print("Enter CVV: ")
		byteCVV, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read CVV: %w", err)
		}
		fmt.Println()
		cvv = string(byteCVV)
	}

	notes, _ := cmd.Flags().GetString("notes")

	data := &models.CardData{
		Number:     number,
		Holder:     holder,
		ExpiryDate: expiry,
		CVV:        cvv,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	encryptedData, err := app.Encryptor.EncryptBytes(jsonData)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	secret := &models.Secret{
		UserID:        app.Config.UserID,
		Name:          name,
		DataType:      models.DataTypeCard,
		EncryptedData: encryptedData,
		Metadata:      notes,
	}

	if err := app.Storage.CreateSecret(secret); err != nil {
		return fmt.Errorf("failed to save secret: %w", err)
	}

	fmt.Printf("Card '%s' added successfully (ID: %s)\n", name, secret.ID)
	return nil
}

func runAddFile(cmd *cobra.Command, args []string) error {
	if err := requireAuth(cmd); err != nil {
		return err
	}
	if err := requireEncryptionKey(cmd); err != nil {
		return err
	}

	app := getApp(cmd)

	filepath := args[0]

	fileData, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	name, _ := cmd.Flags().GetString("name")
	if name == "" {
		name = filepath
		lastSlash := strings.LastIndex(filepath, "/")
		if lastSlash != -1 {
			name = filepath[lastSlash+1:]
		}
	}

	notes, _ := cmd.Flags().GetString("notes")

	data := &models.BinaryData{
		Data:     fileData,
		FileName: name,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	encryptedData, err := app.Encryptor.EncryptBytes(jsonData)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	secret := &models.Secret{
		UserID:        app.Config.UserID,
		Name:          name,
		DataType:      models.DataTypeBinary,
		EncryptedData: encryptedData,
		Metadata:      notes,
	}

	if err := app.Storage.CreateSecret(secret); err != nil {
		return fmt.Errorf("failed to save secret: %w", err)
	}

	fmt.Printf("File '%s' added successfully (ID: %s, size: %d bytes)\n", name, secret.ID, len(fileData))
	return nil
}

func runGet(cmd *cobra.Command, args []string) error {
	if err := requireAuth(cmd); err != nil {
		return err
	}
	if err := requireEncryptionKey(cmd); err != nil {
		return err
	}

	app := getApp(cmd)

	id := args[0]

	secret, err := app.Storage.GetSecret(id)
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	decryptedData, err := app.Encryptor.DecryptBytes(secret.EncryptedData)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %w", err)
	}

	fmt.Printf("\n=== %s ===\n", secret.Name)
	fmt.Printf("ID: %s\n", secret.ID)
	fmt.Printf("Type: %s\n", secret.DataType.String())
	fmt.Printf("Created: %s\n", secret.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Updated: %s\n", secret.UpdatedAt.Format("2006-01-02 15:04:05"))
	if secret.Metadata != "" {
		fmt.Printf("Notes: %s\n", secret.Metadata)
	}
	fmt.Println()

	switch secret.DataType {
	case models.DataTypeLoginPassword:
		var data models.LoginPassword
		if err := json.Unmarshal(decryptedData, &data); err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
		}
		fmt.Printf("Login: %s\n", data.Login)
		fmt.Printf("Password: %s\n", data.Password)
		if data.URL != "" {
			fmt.Printf("URL: %s\n", data.URL)
		}

	case models.DataTypeText:
		var data models.TextData
		if err := json.Unmarshal(decryptedData, &data); err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
		}
		fmt.Printf("Text:\n%s\n", data.Text)

	case models.DataTypeCard:
		var data models.CardData
		if err := json.Unmarshal(decryptedData, &data); err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
		}
		fmt.Printf("Card Number: %s\n", data.Number)
		fmt.Printf("Holder: %s\n", data.Holder)
		fmt.Printf("Expiry: %s\n", data.ExpiryDate)
		fmt.Printf("CVV: %s\n", data.CVV)

	case models.DataTypeBinary:
		var data models.BinaryData
		if err := json.Unmarshal(decryptedData, &data); err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
		}
		fmt.Printf("File: %s (%d bytes)\n", data.FileName, len(data.Data))
		fmt.Println("Use 'gophkeeper get [id] --output=filename' to save the file")
	}

	return nil
}

func runList(cmd *cobra.Command, args []string) error {
	if err := requireAuth(cmd); err != nil {
		return err
	}

	app := getApp(cmd)

	typeFilter, _ := cmd.Flags().GetString("type")

	var secrets []models.Secret
	var err error

	if typeFilter != "" {
		dataType := models.ParseDataType(typeFilter)
		if dataType == 0 {
			return fmt.Errorf("invalid type: %s (use: password, text, binary, card)", typeFilter)
		}
		secrets, err = app.Storage.GetSecretsByType(dataType)
	} else {
		secrets, err = app.Storage.GetAllSecrets()
	}

	if err != nil {
		return fmt.Errorf("failed to list secrets: %w", err)
	}

	if len(secrets) == 0 {
		fmt.Println("No secrets found")
		return nil
	}

	fmt.Printf("\n%-36s  %-15s  %-20s  %s\n", "ID", "TYPE", "NAME", "UPDATED")
	fmt.Println(strings.Repeat("-", 90))

	for _, secret := range secrets {
		name := secret.Name
		if len(name) > 20 {
			name = name[:17] + "..."
		}
		fmt.Printf("%-36s  %-15s  %-20s  %s\n",
			secret.ID,
			secret.DataType.String(),
			name,
			secret.UpdatedAt.Format("2006-01-02 15:04"),
		)
	}

	fmt.Printf("\nTotal: %d secrets\n", len(secrets))
	return nil
}

func runDelete(cmd *cobra.Command, args []string) error {
	if err := requireAuth(cmd); err != nil {
		return err
	}

	app := getApp(cmd)

	id := args[0]
	force, _ := cmd.Flags().GetBool("force")

	secret, err := app.Storage.GetSecret(id)
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	if !force {
		fmt.Printf("Are you sure you want to delete '%s'? [y/N]: ", secret.Name)
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Cancelled")
			return nil
		}
	}

	if err := app.Storage.DeleteSecret(id); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	fmt.Printf("Secret '%s' deleted\n", secret.Name)
	return nil
}