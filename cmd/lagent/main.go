package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/connector"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
	"software.sslmate.com/src/go-pkcs12"
)

func agent(args []string) error {
	credential := ""
	backend := ""
	host := "127.0.0.1:443"
	debug := false
	fs := pflag.NewFlagSet("lagent", pflag.ExitOnError)
	fs.StringVarP(&credential, "credential", "k", credential, "Credential file")
	fs.StringVarP(&backend, "backend", "b", backend, "Backend service")
	fs.StringVarP(&host, "host", "h", host, "Connect host")
	fs.BoolVar(&debug, "debug", debug, "Show debug log")
	if err := fs.Parse(args); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	logLevel := "info"
	if debug {
		logLevel = "debug"
	}

	b, err := ioutil.ReadFile(credential)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	privateKey, cert, caCerts, err := pkcs12.DecodeChain(b, connector.DefaultCertificatePassword)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	err = logger.Init(&config.Logger{
		Level:    logLevel,
		Encoding: "console",
	})
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	agent := connector.NewAgent(cert, privateKey, caCerts, backend)
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
