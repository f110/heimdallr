package main

import (
	"fmt"
	"os"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/cmd/heimctl"
)

func cli(args []string) error {
	rootCmd := &cmd.Command{
		Use:   "heimctl",
		Short: "heimctl is the manager command for heimdallr proxy",
	}

	heimctl.Version(rootCmd)
	heimctl.Bootstrap(rootCmd)
	heimctl.Admin(rootCmd)
	heimctl.Cluster(rootCmd)
	heimctl.Util(rootCmd)
	heimctl.Generate(rootCmd)
	heimctl.EtcdCluster(rootCmd)

	return rootCmd.Execute(args)
}

func main() {
	if err := cli(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
