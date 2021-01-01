package tunnel

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

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

func Info(rootCmd *cobra.Command) {
	infoCmd := &cobra.Command{
		Use:   "info",
		Short: "Show the information of the certificate",
		RunE: func(_ *cobra.Command, _ []string) error {
			return info()
		},
	}

	rootCmd.AddCommand(infoCmd)
}
