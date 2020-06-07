package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/pflag"

	"go.f110.dev/heimdallr/pkg/cmd/reverseproxy"
	"go.f110.dev/heimdallr/pkg/version"
)

func printVersion() {
	fmt.Printf("Version: %s\n", version.Version)
	fmt.Printf("Go version: %s\n", runtime.Version())
}

func command(args []string) error {
	confFile := ""
	version := false
	fs := pflag.NewFlagSet("heimdallr-proxy", pflag.ContinueOnError)
	fs.StringVarP(&confFile, "config", "c", confFile, "Config file")
	fs.BoolVarP(&version, "version", "v", version, "Show version")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if version {
		printVersion()
		return nil
	}

	process := reverseproxy.New()
	process.ConfFile = confFile
	process.Loop()

	return nil
}

func main() {
	if err := command(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
