package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/pflag"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/cmd/discovery"
	"go.f110.dev/heimdallr/pkg/logger"
)

func dnsSidecar(args []string) error {
	fs := pflag.NewFlagSet("dns-sidecar", pflag.ContinueOnError)
	process := discovery.New()
	process.Flags(fs)
	logger.Flags(fs)
	if err := fs.Parse(args); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	process.SignalHandling(os.Interrupt, syscall.SIGTERM)
	if err := process.Loop(); err != nil {
		return err
	}

	return nil
}

func main() {
	if err := dnsSidecar(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%+v", err)
		os.Exit(1)
	}
}
