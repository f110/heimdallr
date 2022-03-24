package main

import (
	"fmt"
	"os"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/cmd/release"
)

func releaseCmd(args []string) error {
	rootCmd := &cmd.Command{
		Use: "release",
	}

	release.GitHub(rootCmd)
	release.Container(rootCmd)
	release.ManifestCleaner(rootCmd)

	return rootCmd.Execute(args)
}

func main() {
	if err := releaseCmd(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
