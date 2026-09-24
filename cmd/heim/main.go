package main

import (
	"fmt"
	"os"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/cmd/heim"
)

func heimCli(args []string) error {
	rootCmd := &cmd.Command{Use: "heim"}

	heim.Login(rootCmd)

	return rootCmd.Execute(args)
}

func main() {
	if err := heimCli(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
