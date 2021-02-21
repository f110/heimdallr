package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
	"software.sslmate.com/src/go-pkcs12"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/connector"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/version"
)

func printVersion() {
	fmt.Printf("Version: %s\n", version.Version)
	fmt.Printf("Go version: %s\n", runtime.Version())
}

func useCertificateAndPrivateKey(name, certFilePath, privateKeyPath, caCertPath string) (*x509.Certificate, crypto.PrivateKey, []*x509.Certificate, error) {
	_, err := os.Stat(privateKeyPath)
	if os.IsNotExist(err) {
		subject := pkix.Name{CommonName: name}
		csr, key, err := cert.CreatePrivateKeyAndCertificateRequest(subject, []string{})
		if err != nil {
			return nil, nil, nil, xerrors.Errorf(": %v", err)
		}

		b, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, nil, nil, xerrors.Errorf(": %v", err)
		}
		buf := new(bytes.Buffer)
		if err := pem.Encode(buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
			return nil, nil, nil, xerrors.Errorf(": %v", err)
		}
		if err := os.WriteFile(privateKeyPath, buf.Bytes(), 0400); err != nil {
			return nil, nil, nil, xerrors.Errorf(": %v", err)
		}

		f, err := os.CreateTemp("", "csr")
		if err != nil {
			return nil, nil, nil, xerrors.Errorf(": %v", err)
		}
		f.Write(csr)
		f.Close()
		fmt.Fprintf(os.Stderr, "Create CSR: %s\n", f.Name())
		return nil, nil, nil, xerrors.New("Send CSR to the administrator")
	}
	if err != nil {
		return nil, nil, nil, err
	}

	_, err = os.Stat(certFilePath)
	if os.IsNotExist(err) {
		return nil, nil, nil, xerrors.New("certificate not found. please pass a cert path to --certificate")
	}
	if err != nil {
		return nil, nil, nil, err
	}

	b, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf(": %v", err)
	}
	block, _ := pem.Decode(b)
	if block.Type != "EC PRIVATE KEY" {
		return nil, nil, nil, xerrors.New("invalid private key")
	}
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf(": %v", err)
	}

	b, err = os.ReadFile(certFilePath)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf(": %v", err)
	}
	block, _ = pem.Decode(b)
	if block.Type != "CERTIFICATE" {
		return nil, nil, nil, xerrors.New("invalid certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf(": %v", err)
	}

	var caCertificates []*x509.Certificate
	if caCertPath != "" {
		b, err = os.ReadFile(caCertPath)
		if err != nil {
			return nil, nil, nil, xerrors.Errorf(": %v", err)
		}
		for {
			block, rest := pem.Decode(b)
			if block.Type != "CERTIFICATE" {
				return nil, nil, nil, xerrors.Errorf(": %v", err)
			}
			caCertificate, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, nil, xerrors.Errorf(": %v", err)
			}
			caCertificates = append(caCertificates, caCertificate)

			if len(rest) != 0 {
				b = rest
			} else {
				break
			}
		}
	}

	return certificate, privateKey, caCertificates, nil
}

func agent(args []string) error {
	credential := ""
	certificate := ""
	privateKey := ""
	backend := ""
	name := ""
	caCertPath := ""
	host := "127.0.0.1:443"
	serverName := ""
	debug := false
	v := false
	fs := pflag.NewFlagSet("heim-connector", pflag.ExitOnError)
	fs.StringVarP(&credential, "credential", "k", credential, "Credential file for proxy (p12)")
	fs.StringVarP(&certificate, "certificate", "c", certificate, "Signed certificate file path")
	fs.StringVarP(&privateKey, "privatekey", "p", privateKey, "Private Key file path. If file is not exists, agent will be create a new private key.")
	fs.StringVar(&caCertPath, "ca-cert", caCertPath, "CA Certificate file path")
	fs.StringVarP(&backend, "backend", "b", backend, "Backend address")
	fs.StringVarP(&host, "host", "h", host, "Proxy host")
	fs.StringVar(&serverName, "server-name", "", "Name of server")
	fs.StringVarP(&name, "name", "n", name, "Name of this agent")
	fs.BoolVar(&debug, "debug", debug, "Show debug log")
	fs.BoolVarP(&v, "version", "v", v, "Show version")
	if err := fs.Parse(args); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	logLevel := "info"
	if debug {
		logLevel = "debug"
	}

	if v {
		printVersion()
		return nil
	}

	var myCert *x509.Certificate
	var caCerts []*x509.Certificate
	var privKey crypto.PrivateKey
	var err error
	if privateKey != "" {
		myCert, privKey, caCerts, err = useCertificateAndPrivateKey(name, certificate, privateKey, caCertPath)
		if err != nil {
			return err
		}
	} else if credential != "" {
		b, err := os.ReadFile(credential)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		privateKey, c, caC, err := pkcs12.DecodeChain(b, connector.DefaultCertificatePassword)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		myCert = c
		caCerts = caC
		privKey = privateKey
	} else {
		return xerrors.New("privatekey or credential is required")
	}

	err = logger.Init(&configv2.Logger{
		Level:    logLevel,
		Encoding: "console",
	})
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	agent := connector.NewAgent(myCert, privKey, caCerts, backend)
	if err := agent.Connect(host, serverName); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	return agent.Serve()
}

func main() {
	if err := agent(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%+v", err)
		os.Exit(1)
	}
}
