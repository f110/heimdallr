package heimctl

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/config/configreader"
)

func Util(rootCmd *cobra.Command) {
	util := &cobra.Command{
		Use:   "util",
		Short: "Utilities",
	}
	util.AddCommand(githubSignature())
	util.AddCommand(webhookCert())

	rootCmd.AddCommand(util)
}

func githubSignature() *cobra.Command {
	confFile := ""
	body := ""

	ghSignature := &cobra.Command{
		Use:   "github-signature",
		Short: "Generate a signature of webhook of github",
		RunE: func(_ *cobra.Command, _ []string) error {
			conf, err := configreader.ReadConfig(confFile)
			if err != nil {
				return err
			}
			h := hmac.New(sha1.New, conf.AccessProxy.Credential.GithubWebhookSecret)
			h.Write([]byte(body))
			hash := h.Sum(nil)
			fmt.Fprintf(os.Stdout, "sha1=%s", hex.EncodeToString(hash[:]))

			return nil
		},
	}
	ghSignature.Flags().StringVarP(&confFile, "config", "c", confFile, "Config file")
	ghSignature.Flags().StringVarP(&body, "body", "d", body, "Request body")

	return ghSignature
}

func webhookCert() *cobra.Command {
	commonName := ""
	certificateFile := ""
	privateKeyFile := ""

	wc := &cobra.Command{
		Use:   "webhook-cert",
		Short: "Generating the server certificate for Admission webhook server",
		RunE: func(_ *cobra.Command, args []string) error {
			if _, err := os.Stat(certificateFile); err == nil {
				return xerrors.Errorf("%s is exist", certificateFile)
			}
			if _, err := os.Stat(privateKeyFile); err == nil {
				return xerrors.Errorf("%s is exist", privateKeyFile)
			}

			privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}

			template := &x509.Certificate{
				SerialNumber: serial,
				Subject: pkix.Name{
					CommonName: commonName,
				},
				NotBefore:             time.Now().UTC(),
				NotAfter:              time.Now().AddDate(2, 0, 0).UTC(),
				DNSNames:              []string{commonName},
				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				BasicConstraintsValid: true,
				SignatureAlgorithm:    x509.ECDSAWithSHA256,
			}
			certByte, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			buf := new(bytes.Buffer)
			if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: certByte}); err != nil {
				return xerrors.Errorf(": %w", err)
			}
			if err := ioutil.WriteFile(certificateFile, buf.Bytes(), 0644); err != nil {
				return xerrors.Errorf(": %w", err)
			}
			buf.Reset()
			b, err := x509.MarshalECPrivateKey(privKey)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			if err := pem.Encode(buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
				return xerrors.Errorf(": %w", err)
			}
			if err := ioutil.WriteFile(privateKeyFile, buf.Bytes(), 0644); err != nil {
				return xerrors.Errorf(": %w", err)
			}

			return nil
		},
	}
	wc.Flags().StringVar(&commonName, "common-name", "", "Common Name. This value will used at SAN")
	wc.Flags().StringVar(&privateKeyFile, "private-key", "", "File path of private key")
	wc.Flags().StringVar(&certificateFile, "certificate", "", "File path of certificate")
	_ = wc.MarkFlagRequired("common-name")
	_ = wc.MarkFlagRequired("private-key")
	_ = wc.MarkFlagRequired("certificate")

	return wc
}
