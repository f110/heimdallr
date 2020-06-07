package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/pflag"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/cmd/rpcserver"
	"go.f110.dev/heimdallr/pkg/version"
)

func printVersion() {
	fmt.Printf("Version: %s\n", version.Version)
	fmt.Printf("Go version: %s\n", runtime.Version())
}

func rpcServer(args []string) error {
	confFile := ""
	v := false
	fs := pflag.NewFlagSet("heim-rpcserver", pflag.ContinueOnError)
	fs.StringVarP(&confFile, "config", "c", confFile, "Config file")
	fs.BoolVarP(&v, "version", "v", v, "Show version")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if v {
		printVersion()
		return nil
	}

	process := rpcserver.New()
	if err := process.ReadConfig(confFile); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if err := process.Setup(); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if err := process.Start(); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	process.Wait()

	return process.Err
}

func main() {
	if err := rpcServer(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
