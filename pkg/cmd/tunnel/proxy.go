package tunnel

import (
	"context"
	"net"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/auth/token"
	"go.f110.dev/heimdallr/pkg/authproxy"
	"go.f110.dev/heimdallr/pkg/config/userconfig"
)

func proxy(args []string) error {
	uc, err := userconfig.New()
	if err != nil {
		return err
	}

	to, err := uc.GetToken()
	if err != nil {
		return err
	}
	clientCert, err := uc.GetCertificate()
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
	err = client.Dial(host, port, clientCert, to)
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

func Proxy(rootCmd *cobra.Command) {
	proxyCmd := &cobra.Command{
		Use:   "proxy [host]",
		Short: "Proxy to backend",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return proxy(args)
		},
	}

	rootCmd.AddCommand(proxyCmd)
}
