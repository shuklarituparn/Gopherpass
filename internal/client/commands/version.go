package commands

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Print version, build date, and commit information for the GophKeeper client.`,
	Run:   runVersion,
}

func runVersion(cmd *cobra.Command, args []string) {
	fmt.Printf("GophKeeper Client\n")
	fmt.Printf("  Version:    %s\n", BuildVersion)
	fmt.Printf("  Build Date: %s\n", BuildDate)
	fmt.Printf("  Commit:     %s\n", BuildCommit)
	fmt.Printf("  Go Version: %s\n", runtime.Version())
	fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
}
