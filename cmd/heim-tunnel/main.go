package main

import (
	"os"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/cmd/tunnel"
)

func tunnelCli(args []string) error {
	rootCmd := &cmd.Command{Use: "heim-tunnel"}

	tunnel.Init(rootCmd)
	tunnel.Info(rootCmd)
	tunnel.Proxy(rootCmd)

	return rootCmd.Execute(args)
}

func main() {
	if err := tunnelCli(os.Args); err != nil {
		cmd.PrintError(os.Stderr, err)
		os.Exit(1)
	}
}
