package tunnel

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/config/userconfig"
)

func info() error {
	uc, err := userconfig.New()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	c, err := uc.GetCertificate()
	if err == nil {
		ce, err := x509.ParseCertificate(c.Certificate[0])
		if err == nil {
			fmt.Printf("Certificate loaded: %s\n", ce.Subject.CommonName)
			fmt.Printf("\texpire at: %s\n", ce.NotAfter.Format(time.RFC3339))
		}
	}

	return nil
}

func Info(rootCmd *cmd.Command) {
	infoCmd := &cmd.Command{
		Use:   "info",
		Short: "Show the information of the certificate",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			return info()
		},
	}

	rootCmd.AddCommand(infoCmd)
}
