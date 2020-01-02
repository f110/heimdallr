package main

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/f110/lagrangian-proxy/pkg/auth/token"
	"github.com/f110/lagrangian-proxy/pkg/localproxy"
	"github.com/f110/lagrangian-proxy/pkg/version"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
)

func printVersion() {
	fmt.Printf("Version: %s\n", version.Version)
	fmt.Printf("Go version: %s\n", runtime.Version())
}

func proxy(args []string) error {
	v := false
	fs := pflag.NewFlagSet("lag-proxy", pflag.ContinueOnError)
	fs.BoolVarP(&v, "version", "v", v, "Show version")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if v {
		printVersion()
		return nil
	}

	idp := localproxy.NewIdentityProvider("token")
	if _, err := idp.Provide(); err != nil {
		return xerrors.Errorf(": %v", err)
	}

	tokenClient := token.NewTokenClient("token")
	t, err := tokenClient.GetToken()
	if err != nil {
		return err
	}

	client := localproxy.NewClient(os.Stdin, os.Stdout)
Retry:
	err = client.Dial(args[0], t)
	if err != nil {
		e, ok := err.(*localproxy.ErrorTokenAuthorization)
		if ok {
			t, err := tokenClient.RequestToken(e.Endpoint)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			t = t
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
