package lagctl

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/f110/lagrangian-proxy/pkg/version"
)

func Version(rootCmd *cobra.Command) {
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version",
		RunE: func(_ *cobra.Command, _ []string) error {
			fmt.Printf("Version: %s\n", version.Version)
			fmt.Printf("Go version: %s\n", runtime.Version())
			return nil
		},
	}
	rootCmd.AddCommand(versionCmd)
}
