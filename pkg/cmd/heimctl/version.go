package heimctl

import (
	"context"
	"fmt"
	"runtime"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/version"
)

func Version(rootCmd *cmd.Command) {
	versionCmd := &cmd.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			fmt.Printf("Version: %s\n", version.Version)
			fmt.Printf("Go version: %s\n", runtime.Version())
			return nil
		},
	}
	rootCmd.AddCommand(versionCmd)
}
