package main

import (
	"os"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/cmd/heim"
)

func heimCli(args []string) error {
	rootCmd := &cmd.Command{Use: "heim"}

	heim.Login(rootCmd)
	heim.Token(rootCmd)
	heim.MCP(rootCmd)

	return rootCmd.Execute(args)
}

func main() {
	if err := heimCli(os.Args); err != nil {
		cmd.PrintError(os.Stderr, err)
		os.Exit(1)
	}
}
