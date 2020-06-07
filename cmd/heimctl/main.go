package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"go.f110.dev/heimdallr/pkg/cmd/lagctl"
)

func cli(args []string) error {
	rootCmd := &cobra.Command{Use: "heimctl"}

	lagctl.Version(rootCmd)
	lagctl.Bootstrap(rootCmd)
	lagctl.Admin(rootCmd)
	lagctl.Cluster(rootCmd)
	lagctl.TestServer(rootCmd)
	lagctl.Util(rootCmd)

	rootCmd.SetArgs(args)
	return rootCmd.Execute()
}

func main() {
	if err := cli(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
