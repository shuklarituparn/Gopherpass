package commands

import (
	"context"
	"fmt"
	"sync"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/shuklarituparn/Gopherpass/internal/models"
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

const syncConcurrencyLimit = 10

func runSync(cmd *cobra.Command, args []string) error {
	if err := requireAuth(cmd); err != nil {
		return err
	}

	app := getApp(cmd)

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

	updated, updateWarnings := processUpdatesParallel(cmd.Context(), app, resp.UpdatedSecrets)

	deleted, deleteWarnings := processDeletionsParallel(cmd.Context(), app, resp.DeletedIDs)

	markWarnings := markSyncedParallel(cmd.Context(), app, localChanges)

	for _, w := range updateWarnings {
		fmt.Printf("Warning: %s\n", w)
	}
	for _, w := range deleteWarnings {
		fmt.Printf("Warning: %s\n", w)
	}
	for _, w := range markWarnings {
		fmt.Printf("Warning: %s\n", w)
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


func processUpdatesParallel(ctx context.Context, app *App, secrets []models.Secret) (int, []string) {
	if len(secrets) == 0 {
		return 0, nil
	}

	var (
		updated  int
		mu       sync.Mutex
		warnings []string
	)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(syncConcurrencyLimit)

	for _, secret := range secrets {
		secret := secret
		g.Go(func() error {
			if err := app.Storage.UpsertSecret(&secret); err != nil {
				mu.Lock()
				warnings = append(warnings, fmt.Sprintf("failed to update secret %s: %v", secret.ID, err))
				mu.Unlock()
				return nil 
			}
			mu.Lock()
			updated++
			mu.Unlock()
			return nil
		})
	}

	_ = g.Wait()
	return updated, warnings
}


func processDeletionsParallel(ctx context.Context, app *App, ids []string) (int, []string) {
	if len(ids) == 0 {
		return 0, nil
	}

	var (
		deleted  int
		mu       sync.Mutex
		warnings []string
	)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(syncConcurrencyLimit)

	for _, id := range ids {
		id := id 
		g.Go(func() error {
			if err := app.Storage.DeleteSecretPermanently(id); err != nil {
				mu.Lock()
				warnings = append(warnings, fmt.Sprintf("failed to delete secret %s: %v", id, err))
				mu.Unlock()
				return nil 
			}
			mu.Lock()
			deleted++
			mu.Unlock()
			return nil
		})
	}

	_ = g.Wait() 
	return deleted, warnings
}


func markSyncedParallel(ctx context.Context, app *App, secrets []models.Secret) []string {
	if len(secrets) == 0 {
		return nil
	}

	var (
		mu       sync.Mutex
		warnings []string
	)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(syncConcurrencyLimit)

	for _, secret := range secrets {
		secret := secret
		g.Go(func() error {
			if err := app.Storage.MarkAsSynced(secret.ID); err != nil {
				mu.Lock()
				warnings = append(warnings, fmt.Sprintf("failed to mark secret %s as synced: %v", secret.ID, err))
				mu.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait()
	return warnings
}