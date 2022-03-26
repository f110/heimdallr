package tunnel

import (
	"context"
	"net"
	"os"
	"strings"

	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/auth/token"
	"go.f110.dev/heimdallr/pkg/authproxy"
	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/config/userconfig"
)

func proxy(args []string, resolverAddr, overrideOpenURLCommand string, insecure bool) error {
	uc, err := userconfig.New()
	if err != nil {
		return err
	}

	accessToken, err := uc.GetToken()
	if err != nil {
		return err
	}
	clientCert, err := uc.GetCertificate()
	if err != nil {
		return err
	}

	var hostname, port string
	if strings.Contains(args[0], ":") {
		h, p, err := net.SplitHostPort(args[0])
		if err != nil {
			return err
		}
		hostname = h
		port = p
	} else {
		hostname = args[0]
		port = "443"
	}
	resolver := net.DefaultResolver
	if resolverAddr != "" {
		d := net.Dialer{}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, resolverAddr)
			},
		}
	}

	client := authproxy.NewSocketProxyClient(os.Stdin, os.Stdout)
Retry:
	err = client.Dial(hostname, port, clientCert, accessToken, resolver, insecure)
	if err != nil {
		e, ok := err.(*authproxy.ErrorTokenAuthorization)
		if ok {
			tokenClient := token.NewClient(resolver)
			t, err := tokenClient.RequestToken(e.Endpoint, overrideOpenURLCommand, insecure)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			accessToken = t
			if err := uc.SetToken(accessToken); err != nil {
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

func Proxy(rootCmd *cmd.Command) {
	resolverAddr := ""
	overrideOpenURLCommand := ""
	insecure := false
	proxyCmd := &cmd.Command{
		Use:   "proxy",
		Short: "Proxy to backend",
		Run: func(_ context.Context, _ *cmd.Command, args []string) error {
			return proxy(args, resolverAddr, overrideOpenURLCommand, insecure)
		},
	}
	proxyCmd.Flags().String("override-open-url-command", "Override command for opening URL").Var(&overrideOpenURLCommand)
	proxyCmd.Flags().String("resolver", "Resolver address").Var(&resolverAddr)
	proxyCmd.Flags().Bool("insecure", "Skip verification").Var(&insecure)

	rootCmd.AddCommand(proxyCmd)
}
