package tunnel

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/config/userconfig"
)

func initializeTunnel(force bool) error {
	uc, err := userconfig.New()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if !force {
		if v, err := uc.GetCertificate(); err == nil && v != nil {
			fmt.Println("Already initialized. If you want to set it up again, use --force flag")
			return nil
		}
	}

	csr, err := uc.GetCSR()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	fmt.Println("Please regist following CSR to your dashboard")
	fmt.Print(string(csr))
	fmt.Println()
	fmt.Println("After you get certificate, you will load it to using --certificate option.")
	fmt.Println("\theim-tunnel init --certificate cert.crt")

	return nil
}

func loadCertificate(p string) error {
	uc, err := userconfig.New()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	buf, err := ioutil.ReadFile(p)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	block, _ := pem.Decode(buf)
	if block.Type != "CERTIFICATE" {
		return xerrors.New("is not certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := uc.SetCertificate(c); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	fmt.Println("Loading certificate was succeeded")

	return nil
}

func Init(rootCmd *cobra.Command) {
	force := false
	certificate := ""
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize the command",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if certificate != "" {
				return loadCertificate(certificate)
			} else {
				return initializeTunnel(force)
			}
		},
	}
	initCmd.Flags().BoolVar(&force, "force", false, "Set up forcibly")
	initCmd.Flags().StringVar(&certificate, "certificate", "", "The file path of certificate")

	rootCmd.AddCommand(initCmd)
}
