package heim

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"

	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/config/userconfig"
)

const tokenFormatHeaders = "headers"

func printToken(w io.Writer, uc *userconfig.UserDir, format string) error {
	if format != "" && format != tokenFormatHeaders {
		return xerrors.Newf("unsupported format: %s", format)
	}

	t, err := uc.GetToken()
	if err != nil {
		return err
	}
	if t.IsExpired() {
		server := "<server>"
		if t != nil {
			if u, err := url.Parse(t.Endpoint); err == nil && u.Host != "" {
				server = u.Host
			}
		}
		return xerrors.Newf("the token is expired or not found. run `heim login %s`", server)
	}

	switch format {
	case tokenFormatHeaders:
		if err := json.NewEncoder(w).Encode(map[string]string{"Authorization": "Bearer " + t.Token}); err != nil {
			return xerrors.WithStack(err)
		}
	default:
		if _, err := fmt.Fprintln(w, t.Token); err != nil {
			return xerrors.WithStack(err)
		}
	}

	return nil
}

func Token(rootCmd *cmd.Command) {
	format := ""
	tokenCmd := &cmd.Command{
		Use:   "token",
		Short: "Print the access token",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			uc, err := userconfig.New()
			if err != nil {
				return err
			}
			return printToken(os.Stdout, uc, format)
		},
	}
	tokenCmd.Flags().String("format", "Output format. If \"headers\" is given, print the JSON object of HTTP headers").Var(&format)

	rootCmd.AddCommand(tokenCmd)
}
