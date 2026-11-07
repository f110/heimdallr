package tunnel

import (
	"context"
	"fmt"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/version"
)

func Version(rootCmd *cmd.Command) {
	versionCmd := &cmd.Command{
		Use:   "version",
		Short: "Show version",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			fmt.Printf("Version: %s\n", version.Version)
			return nil
		},
	}

	rootCmd.AddCommand(versionCmd)
}
