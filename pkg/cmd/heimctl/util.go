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

	"go.f110.dev/heimdallr/pkg/cert"
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
	util.AddCommand(webhookCACert())
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
	var commonName, caCertificateFile, caPrivateKeyFile, certificateFile, privateKeyFile string

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

			b, err := os.ReadFile(caCertificateFile)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			block, _ := pem.Decode(b)
			caCert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			b, err = os.ReadFile(caPrivateKeyFile)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			block, _ = pem.Decode(b)
			caPrivateKey, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return xerrors.Errorf(": %v", err)
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
			certByte, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caPrivateKey)
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
			b, err = x509.MarshalECPrivateKey(privKey)
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
	wc.Flags().String("ca-certificate", "File path of the certificate of CA").Var(&caCertificateFile).Required()
	wc.Flags().String("ca-private-key", "File path of the private key of CA").Var(&caPrivateKeyFile).Required()
	wc.Flags().String("common-name", "Common Name. This value will used at SAN").Var(&commonName).Required()
	wc.Flags().String("private-key", "File path of private key").Var(&privateKeyFile).Required()
	wc.Flags().String("certificate", "File path of certificate").Var(&certificateFile).Required()

	return wc
}

func webhookCACert() *cmd.Command {
	var certificateFile, privateKeyFile string

	cac := &cmd.Command{
		Use:   "webhook-ca-cert",
		Short: "Generate the CA certificate for Admission webhook server",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			if _, err := os.Stat(certificateFile); err == nil {
				return xerrors.Errorf("%s is exist", certificateFile)
			}
			if _, err := os.Stat(privateKeyFile); err == nil {
				return xerrors.Errorf("%s is exist", privateKeyFile)
			}

			caCert, privKey, err := cert.CreateCertificateAuthority("heimdallr-operator CA", "", "", "", "ecdsa")
			if err != nil {
				return err
			}
			buf := new(bytes.Buffer)
			if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}); err != nil {
				return xerrors.Errorf(": %w", err)
			}
			if err := os.WriteFile(certificateFile, buf.Bytes(), 0644); err != nil {
				return xerrors.Errorf(": %w", err)
			}
			buf.Reset()
			b, err := x509.MarshalECPrivateKey(privKey.(*ecdsa.PrivateKey))
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
	cac.Flags().String("certificate", "File path of the certificate").Var(&certificateFile).Required()
	cac.Flags().String("private-key", "File path of the private key").Var(&privateKeyFile).Required()

	return cac
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
