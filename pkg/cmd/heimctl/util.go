package heimctl

import (
	"bytes"
	"context"
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
	"io"
	"math"
	"math/big"
	"os"
	"time"

	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/config/configutil"
)

func Util(rootCmd *cmd.Command) {
	util := &cmd.Command{
		Use:   "util",
		Short: "Utilities",
	}
	util.AddCommand(githubSignature())
	util.AddCommand(webhookCert())
	util.AddCommand(convertV2Config())

	rootCmd.AddCommand(util)
}

func githubSignature() *cmd.Command {
	confFile := ""
	body := ""

	ghSignature := &cmd.Command{
		Use:   "github-signature",
		Short: "Generate a signature of webhook of github",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			conf, err := configutil.ReadConfig(confFile)
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
	ghSignature.Flags().String("config", "Config file").Var(&confFile).Shorthand("c")
	ghSignature.Flags().String("body", "Request body").Var(&body).Shorthand("d")

	return ghSignature
}

func webhookCert() *cmd.Command {
	commonName := ""
	certificateFile := ""
	privateKeyFile := ""

	wc := &cmd.Command{
		Use:   "webhook-cert",
		Short: "Generating the server certificate for Admission webhook server",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
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
			if err := os.WriteFile(certificateFile, buf.Bytes(), 0644); err != nil {
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
			if err := os.WriteFile(privateKeyFile, buf.Bytes(), 0644); err != nil {
				return xerrors.Errorf(": %w", err)
			}

			return nil
		},
	}
	wc.Flags().String("common-name", "Common Name. This value will used at SAN").Var(&commonName).Required()
	wc.Flags().String("private-key", "File path of private key").Var(&privateKeyFile).Required()
	wc.Flags().String("certificate", "File path of certificate").Var(&certificateFile).Required()

	return wc
}

func convertV2Config() *cmd.Command {
	v1Config := ""
	output := ""

	cc := &cmd.Command{
		Use:   "convert-v2-config",
		Short: "Covert to v2 config from v1",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			var outWriter io.Writer
			if output == "" {
				outWriter = os.Stdout
			} else {
				f, err := os.Open(output)
				if err != nil {
					return xerrors.Errorf(": %w", err)
				}
				outWriter = f
			}

			conf := &config.Config{}
			readBuf, err := os.ReadFile(v1Config)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			if err := yaml.Unmarshal(readBuf, &conf); err != nil {
				return xerrors.Errorf(": %w", err)
			}
			v2Conf := configutil.V1ToV2(conf)

			b, err := yaml.Marshal(v2Conf)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			n, err := outWriter.Write(b)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			if len(b) != n {
				return xerrors.New("short write")
			}

			return nil
		},
	}
	cc.Flags().String("config", "Config file which is v1 format").Var(&v1Config).Shorthand("c").Required()
	cc.Flags().String("output", "Output file").Var(&output)

	return cc
}
