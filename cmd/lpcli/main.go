package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"

	"github.com/f110/lagrangian-proxy/pkg/auth"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/gorilla/securecookie"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"
)

func commandBootstrap(args []string) error {
	confFile := ""
	fs := pflag.NewFlagSet("lpcli", pflag.ContinueOnError)
	fs.StringVarP(&confFile, "config", "c", confFile, "Config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	p, err := filepath.Abs(confFile)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	dir := filepath.Dir(p)
	confBuf, err := ioutil.ReadFile(p)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	conf := &config.Config{}
	if err := yaml.Unmarshal(confBuf, conf); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if conf.General == nil || conf.General.CertificateAuthority == nil {
		return xerrors.New("not enough configuration")
	}

	_, err = os.Stat(absPath(conf.General.CertificateAuthority.CertFile, dir))
	certFileExist := !os.IsNotExist(err)
	_, err = os.Stat(absPath(conf.General.CertificateAuthority.KeyFile, dir))
	keyFileExist := !os.IsNotExist(err)
	if !certFileExist && !keyFileExist {
		if err := generateNewCertificateAuthority(conf, dir); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	b, err := ioutil.ReadFile(absPath(conf.General.CertificateAuthority.CertFile, dir))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	block, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	b, err = ioutil.ReadFile(absPath(conf.General.CertificateAuthority.KeyFile, dir))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	block, _ = pem.Decode(b)
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	_, err = os.Stat(absPath(conf.FrontendProxy.CertFile, dir))
	certFileExist = !os.IsNotExist(err)
	_, err = os.Stat(absPath(conf.FrontendProxy.KeyFile, dir))
	keyFileExist = !os.IsNotExist(err)
	if !certFileExist && !keyFileExist {
		if err := createNewServerCertificate(conf, dir, cert, privateKey); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	_, err = os.Stat(absPath(conf.FrontendProxy.SigningSecretKeyFile, dir))
	if os.IsNotExist(err) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		b, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if err := auth.PemEncode(absPath(conf.FrontendProxy.SigningSecretKeyFile, dir), "EC PRIVATE KEY", b); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	_, err = os.Stat(absPath(conf.FrontendProxy.GithubWebHookSecretFile, dir))
	if os.IsNotExist(err) {
		b := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return xerrors.Errorf(": %v", err)
		}
		f, err := os.Create(absPath(conf.FrontendProxy.GithubWebHookSecretFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		f.Write(b)
		f.Close()
	}

	_, err = os.Stat(absPath(conf.FrontendProxy.Session.KeyFile, dir))
	if os.IsNotExist(err) {
		switch conf.FrontendProxy.Session.Type {
		case config.SessionTypeSecureCookie:
			hashKey := securecookie.GenerateRandomKey(32)
			blockKey := securecookie.GenerateRandomKey(16)
			f, err := os.Create(absPath(conf.FrontendProxy.Session.KeyFile, dir))
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			f.WriteString(hex.EncodeToString(hashKey))
			f.WriteString("\n")
			f.WriteString(hex.EncodeToString(blockKey))
			f.Close()
		}
	}

	return nil
}

func generateNewCertificateAuthority(conf *config.Config, dir string) error {
	cert, privateKey, err := auth.CreateCertificateAuthority(conf)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	b, err := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if err := auth.PemEncode(absPath(conf.General.CertificateAuthority.KeyFile, dir), "EC PRIVATE KEY", b); err != nil {
		return xerrors.Errorf(": %v", err)
	}

	if err := auth.PemEncode(absPath(conf.General.CertificateAuthority.CertFile, dir), "CERTIFICATE", cert); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	return nil
}

func createNewServerCertificate(conf *config.Config, dir string, ca *x509.Certificate, caPrivateKey crypto.PrivateKey) error {
	cert, privateKey, err := auth.GenerateServerCertificate(ca, caPrivateKey, 1000, []string{"local-proxy.f110.dev", "*.local-proxy.f110.dev"})

	b, err := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if err := auth.PemEncode(absPath(conf.FrontendProxy.KeyFile, dir), "EC PRIVATE KEY", b); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if err := auth.PemEncode(absPath(conf.FrontendProxy.CertFile, dir), "CERTIFICATE", cert); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	return nil
}

func commandTestServer() error {
	http.HandleFunc("/env", func(w http.ResponseWriter, req *http.Request) {
		b, _ := httputil.DumpRequest(req, false)
		w.Write(b)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "It's working!")
	})
	fmt.Println("Listen :4501")
	return http.ListenAndServe(":4501", nil)
}

func cli(args []string) error {
	switch args[1] {
	case "bootstrap":
		return commandBootstrap(args[2:])
	case "testserver":
		return commandTestServer()
	}

	return nil
}

func absPath(path, dir string) string {
	if strings.HasPrefix(path, "./") {
		a, err := filepath.Abs(filepath.Join(dir, path))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return ""
		}
		return a
	}
	return path
}

func main() {
	if err := cli(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
