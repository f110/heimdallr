package main

import (
	"context"
	"fmt"
	"os"

	"github.com/f110/lagrangian-proxy/pkg/auth/token"
	"github.com/f110/lagrangian-proxy/pkg/localproxy"
	"golang.org/x/xerrors"
)

func proxy(args []string) error {
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
