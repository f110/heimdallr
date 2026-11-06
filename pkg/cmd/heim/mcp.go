package heim

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"time"

	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/auth/token"
	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/cmd/heim/internal/mcpproxy"
	"go.f110.dev/heimdallr/pkg/config/userconfig"
)

func mcpProxy(ctx context.Context, endpoint, server, overrideOpenURLCommand string, authTimeout time.Duration, insecure bool) error {
	uc, err := userconfig.New()
	if err != nil {
		return err
	}

	tokenClient := token.NewClient(net.DefaultResolver)
	login := func(ctx context.Context, endpoint string) (string, time.Time, error) {
		return tokenClient.RequestToken(ctx, endpoint, overrideOpenURLCommand, insecure)
	}
	tokens := mcpproxy.NewTokenSource(uc, server, login, authTimeout)

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecure}
	client := &http.Client{Transport: transport}

	return mcpproxy.New(endpoint, client, tokens).Run(ctx, os.Stdin, os.Stdout)
}

func MCP(rootCmd *cmd.Command) {
	mcpCmd := &cmd.Command{
		Use:   "mcp",
		Short: "Commands for MCP servers",
	}

	server := ""
	overrideOpenURLCommand := ""
	authTimeout := 5 * time.Minute
	insecure := false
	proxyCmd := &cmd.Command{
		Use:   "proxy",
		Short: "Relay MCP messages from stdio to the MCP server. e.g. heim mcp proxy https://mcp.example.com/mcp",
		Run: func(ctx context.Context, _ *cmd.Command, args []string) error {
			if len(args) != 1 {
				return xerrors.New("the URL of the MCP server is required")
			}
			return mcpProxy(ctx, args[0], server, overrideOpenURLCommand, authTimeout, insecure)
		},
	}
	proxyCmd.Flags().String("server", "The token server. If not specified, the server which issued the stored token is used").Var(&server)
	proxyCmd.Flags().Duration("auth-timeout", "Duration to wait for the authentication in the browser").Var(&authTimeout).Default(authTimeout)
	proxyCmd.Flags().String("override-open-url-command", "Override command for opening URL").Var(&overrideOpenURLCommand)
	proxyCmd.Flags().Bool("insecure", "Skip verification").Var(&insecure)
	mcpCmd.AddCommand(proxyCmd)

	rootCmd.AddCommand(mcpCmd)
}
