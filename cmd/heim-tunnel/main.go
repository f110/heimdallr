package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"go.f110.dev/heimdallr/pkg/cmd/tunnel"
)

func tunnelCli(args []string) error {
	rootCmd := &cobra.Command{Use: "heim-tunnel"}

	tunnel.Init(rootCmd)
	tunnel.Info(rootCmd)
	tunnel.Proxy(rootCmd)

	rootCmd.SetArgs(args)
	return rootCmd.Execute()
}

func main() {
	if err := tunnelCli(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
