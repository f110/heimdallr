package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"

	"github.com/spf13/pflag"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/cmd/reverseproxy"
	"go.f110.dev/heimdallr/pkg/version"
)

func printVersion() {
	fmt.Printf("Version: %s\n", version.Version)
	fmt.Printf("Go version: %s\n", runtime.Version())
}

func command(args []string) error {
	confFile := ""
	showVersion := false
	vaultBin := ""
	fs := pflag.NewFlagSet("heimdallr-proxy", pflag.ContinueOnError)
	fs.StringVarP(&confFile, "config", "c", confFile, "Config file")
	fs.BoolVarP(&showVersion, "version", "v", showVersion, "Show version")
	fs.StringVar(&vaultBin, "vault", vaultBin, "A file path of Hashicorp Vault. Development only.")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if showVersion {
		printVersion()
		return nil
	}

	process := reverseproxy.New()
	process.ConfFile = confFile
	process.VaultBin = vaultBin
	go process.SignalHandling(syscall.SIGTERM, syscall.SIGINT)
	if err := process.Loop(); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func main() {
	if err := command(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
