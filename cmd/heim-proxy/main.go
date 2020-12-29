package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/pflag"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/auth/token"
	"go.f110.dev/heimdallr/pkg/authproxy"
	"go.f110.dev/heimdallr/pkg/config/userconfig"
	"go.f110.dev/heimdallr/pkg/version"
)

func printVersion() {
	fmt.Printf("Version: %s\n", version.Version)
	fmt.Printf("Go version: %s\n", runtime.Version())
}

func proxy(args []string) error {
	version := false
	fs := pflag.NewFlagSet("heim-proxy", pflag.ContinueOnError)
	fs.BoolVarP(&version, "version", "v", version, "Show version")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if version {
		printVersion()
		return nil
	}

	uc, err := userconfig.New()
	if err != nil {
		return err
	}

	to, err := uc.GetToken()
	if err != nil {
		return err
	}

	var host, port string
	if strings.Contains(args[0], ":") {
		h, p, err := net.SplitHostPort(args[0])
		if err != nil {
			return err
		}
		host = h
		port = p
	} else {
		host = args[0]
		port = "443"
	}
	client := authproxy.NewSocketProxyClient(os.Stdin, os.Stdout)
Retry:
	err = client.Dial(host, port, to)
	if err != nil {
		e, ok := err.(*authproxy.ErrorTokenAuthorization)
		if ok {
			tokenClient := token.NewClient()
			t, err := tokenClient.RequestToken(e.Endpoint)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			to = t
			if err := uc.SetToken(to); err != nil {
				return err
			}

			goto Retry
		}
		return err
	}
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	err = client.Pipe(ctx)
	return err
}

func main() {
	if err := proxy(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n\x1b[0G", err)
		os.Exit(1)
	}
}
