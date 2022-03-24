package main

import (
	"context"
	"fmt"
	"os"
	"syscall"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/cmd/operator"
	_ "go.f110.dev/heimdallr/pkg/k8s/api/etcd"
	_ "go.f110.dev/heimdallr/pkg/k8s/api/proxy"
)

func controller(args []string) error {
	process := operator.New()

	controllerCmd := &cmd.Command{
		Use: "heimdallrcontroller",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			return process.Loop()
		},
	}

	process.Flags(controllerCmd.Flags())
	process.SignalHandling(syscall.SIGTERM, syscall.SIGINT)

	return controllerCmd.Execute(args)
}

func main() {
	if err := controller(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%+v", err)
		os.Exit(1)
	}
}
