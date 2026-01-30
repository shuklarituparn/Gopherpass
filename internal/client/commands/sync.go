package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Synchronize local data with server",
	Long: `Sync synchronizes your local secrets with the server.
This uploads local changes and downloads updates from the server.`,
	RunE: runSync,
}

func init() {
	syncCmd.Flags().BoolP("force", "f", false, "Force full sync (ignore last sync time)")
}

func runSync(cmd *cobra.Command, args []string) error {
	if err := requireAuth(); err != nil {
		return err
	}

	force, _ := cmd.Flags().GetBool("force")

	fmt.Println("Starting synchronization...")

	lastSyncTime, err := app.Storage.GetLastSyncTime()
	if err != nil {
		return fmt.Errorf("failed to get last sync time: %w", err)
	}

	if force {
		lastSyncTime = lastSyncTime.AddDate(-100, 0, 0) 
		fmt.Println("Forcing full sync...")
	}

	localChanges, err := app.Storage.GetLocallyModifiedSecrets()
	if err != nil {
		return fmt.Errorf("failed to get local changes: %w", err)
	}

	fmt.Printf("Found %d local changes to upload\n", len(localChanges))

	resp, err := app.APIClient.Sync(lastSyncTime, localChanges)
	if err != nil {
		return fmt.Errorf("sync failed: %w", err)
	}

	updated := 0
	for _, secret := range resp.UpdatedSecrets {
		if err := app.Storage.UpsertSecret(&secret); err != nil {
			fmt.Printf("Warning: failed to update secret %s: %v\n", secret.ID, err)
			continue
		}
		updated++
	}

	deleted := 0
	for _, id := range resp.DeletedIDs {
		if err := app.Storage.DeleteSecretPermanently(id); err != nil {
			fmt.Printf("Warning: failed to delete secret %s: %v\n", id, err)
			continue
		}
		deleted++
	}

	for _, secret := range localChanges {
		if err := app.Storage.MarkAsSynced(secret.ID); err != nil {
			fmt.Printf("Warning: failed to mark secret %s as synced: %v\n", secret.ID, err)
		}
	}

	if err := app.Storage.SetLastSyncTime(resp.ServerTime); err != nil {
		return fmt.Errorf("failed to save sync time: %w", err)
	}

	app.Config.LastSyncTime = resp.ServerTime
	if err := app.Config.Save(); err != nil {
		fmt.Printf("Warning: failed to save config: %v\n", err)
	}

	fmt.Println("Synchronization complete:")
	fmt.Printf("  Uploaded: %d changes\n", len(localChanges))
	fmt.Printf("  Downloaded: %d updates\n", updated)
	fmt.Printf("  Deleted: %d items\n", deleted)

	if resp.HasConflicts {
		fmt.Println("\nWarning: There were conflicts during sync. Some changes may need manual resolution.")
	}

	return nil
}
