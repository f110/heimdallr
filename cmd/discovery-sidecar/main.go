package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/pflag"
	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/cmd/discovery"
	"go.f110.dev/heimdallr/pkg/logger"
)

// discovery-sidecar is a sidecar for etcd Pod.
// This sidecar works as DNS server for discovery other member.
//
// Start-up sequence of etcd Pod is a bit more complicated:
//
// 1. If the Pod needs the backup file, start "nc" for receiving the backup file from the controller.
// 2. Start etcd and sidecar container at the same time.
// 3. (sidecar) Sync the cache for the pod informer.
// 4. (sidecar) Start DNS server and waiting for booting it.
// 5. (etcd) Waiting for booting sidecar
// 6. (etcd) Start etcd
//
// After started etcd, discovery-sidecar checks that the process is alive every second.
// It detects process death, then it will be going to shutdown.

func dnsSidecar(args []string) error {
	fs := pflag.NewFlagSet("dns-sidecar", pflag.ContinueOnError)
	process := discovery.New()
	process.Flags(fs)
	logger.Flags(fs)
	if err := fs.Parse(args); err != nil {
		return xerrors.WithStack(err)
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
