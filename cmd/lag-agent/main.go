package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"

	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
	"software.sslmate.com/src/go-pkcs12"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/connector"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/version"
)

func printVersion() {
	fmt.Printf("Version: %s\n", version.Version)
	fmt.Printf("Go version: %s\n", runtime.Version())
}

func agent(args []string) error {
	credential := ""
	privateKey := ""
	backend := ""
	name := ""
	caCertPath := ""
	host := "127.0.0.1:443"
	debug := false
	v := false
	fs := pflag.NewFlagSet("lag-agent", pflag.ExitOnError)
	fs.StringVarP(&credential, "credential", "k", credential, "Credential file (p12)")
	fs.StringVarP(&privateKey, "privatekey", "p", privateKey, "Private Key")
	fs.StringVar(&caCertPath, "ca-cert", caCertPath, "CA Certificate Path")
	fs.StringVarP(&backend, "backend", "b", backend, "Backend service")
	fs.StringVarP(&host, "host", "h", host, "Connect host")
	fs.StringVarP(&name, "name", "n", name, "Name")
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
	if privateKey != "" {
		_, err := os.Stat(privateKey)
		if os.IsNotExist(err) {
			subject := pkix.Name{CommonName: name}
			csr, key, err := cert.CreateCertificateRequest(subject, []string{})
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}

			b, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			buf := new(bytes.Buffer)
			if err := pem.Encode(buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
				return xerrors.Errorf(": %v", err)
			}
			if err := ioutil.WriteFile(privateKey, buf.Bytes(), 0400); err != nil {
				return xerrors.Errorf(": %v", err)
			}

			f, err := ioutil.TempFile("", "csr")
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			f.Write(csr)
			f.Close()
			fmt.Fprintf(os.Stderr, "Create CSR: %s\n", f.Name())
			return xerrors.New("Send CSR to proxy admin")
		} else {
			_, err := os.Stat(credential)
			if os.IsNotExist(err) {
				return xerrors.New("certificate not found. please pass a cert path to -k")
			}

			b, err := ioutil.ReadFile(privateKey)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			block, _ := pem.Decode(b)
			if block.Type != "EC PRIVATE KEY" {
				return xerrors.New("invalid private key")
			}
			privateKey, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			privKey = privateKey

			b, err = ioutil.ReadFile(credential)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			block, _ = pem.Decode(b)
			if block.Type != "CERTIFICATE" {
				return xerrors.New("invalid certificate")
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			myCert = c

			if caCertPath != "" {
				b, err = ioutil.ReadFile(caCertPath)
				if err != nil {
					return xerrors.Errorf(": %v", err)
				}
				block, _ = pem.Decode(b)
				if block.Type != "CERTIFICATE" {
					return xerrors.Errorf(": %v", err)
				}
				c, err = x509.ParseCertificate(block.Bytes)
				if err != nil {
					return xerrors.Errorf(": %v", err)
				}
				caCerts = []*x509.Certificate{c}
			}
		}
	} else if credential != "" {
		b, err := ioutil.ReadFile(credential)
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
	}

	err := logger.Init(&config.Logger{
		Level:    logLevel,
		Encoding: "console",
	})
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	agent := connector.NewAgent(myCert, privKey, caCerts, backend)
	if err := agent.Connect(host); err != nil {
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
