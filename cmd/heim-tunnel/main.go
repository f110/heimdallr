package main

import (
	"fmt"
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
	if err := tunnelCli(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
