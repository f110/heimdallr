package heim

import (
	"context"
	"fmt"
	"net"

	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/auth/token"
	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/config/userconfig"
)

func login(server, overrideOpenURLCommand string, insecure bool) error {
	uc, err := userconfig.New()
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("https://%s/token", server)
	t, expiresAt, err := token.NewClient(net.DefaultResolver).RequestToken(endpoint, overrideOpenURLCommand, insecure)
	if err != nil {
		return err
	}
	if err := uc.SetToken(endpoint, t, expiresAt); err != nil {
		return err
	}

	return nil
}

func Login(rootCmd *cmd.Command) {
	overrideOpenURLCommand := ""
	insecure := false
	loginCmd := &cmd.Command{
		Use:   "login",
		Short: "Get a token from the server. e.g. heim login heimdallr.example.com",
		Run: func(_ context.Context, _ *cmd.Command, args []string) error {
			if len(args) != 1 {
				return xerrors.New("the server name is required")
			}
			return login(args[0], overrideOpenURLCommand, insecure)
		},
	}
	loginCmd.Flags().String("override-open-url-command", "Override command for opening URL").Var(&overrideOpenURLCommand)
	loginCmd.Flags().Bool("insecure", "Skip verification").Var(&insecure)

	rootCmd.AddCommand(loginCmd)
}
