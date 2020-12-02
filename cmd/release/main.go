package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"go.f110.dev/heimdallr/pkg/cmd/release"
)

func releaseCmd(args []string) error {
	rootCmd := &cobra.Command{
		Use: "release",
	}

	release.GitHub(rootCmd)
	release.Container(rootCmd)

	rootCmd.SetArgs(args)
	return rootCmd.Execute()
}

func main() {
	if err := releaseCmd(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
