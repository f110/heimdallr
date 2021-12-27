package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"

	"go.f110.dev/heimdallr/pkg/cmd/operator"
	_ "go.f110.dev/heimdallr/pkg/k8s/api/etcd"
	_ "go.f110.dev/heimdallr/pkg/k8s/api/proxy"
)

func controller(args []string) error {
	process := operator.New()

	cmd := &cobra.Command{
		Use: "heimdallrcontroller",
		RunE: func(_ *cobra.Command, _ []string) error {
			return process.Loop()
		},
	}
	cmd.SetArgs(args)

	process.Flags(cmd.Flags())
	process.SignalHandling(syscall.SIGTERM, syscall.SIGINT)

	return cmd.Execute()
}

func main() {
	if err := controller(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%+v", err)
		os.Exit(1)
	}
}
