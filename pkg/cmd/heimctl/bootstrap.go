package heimctl

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	mrand "math/rand"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/securecookie"
	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/config/configv2"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func bootstrap(confFile string) error {
	p, err := filepath.Abs(confFile)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	dir := filepath.Dir(p)
	confBuf, err := os.ReadFile(p)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	conf := &configv2.Config{}
	if err := yaml.Unmarshal(confBuf, conf); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if conf.AccessProxy == nil || conf.AccessProxy.Credential == nil || conf.CertificateAuthority == nil {
		return xerrors.New("not enough configuration")
	}

	_, err = os.Stat(absPath(conf.CertificateAuthority.Local.CertFile, dir))
	certFileExist := !os.IsNotExist(err)
	_, err = os.Stat(absPath(conf.CertificateAuthority.Local.KeyFile, dir))
	keyFileExist := !os.IsNotExist(err)
	if !certFileExist && !keyFileExist {
		if err := generateNewCertificateAuthority(conf, dir); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	b, err := os.ReadFile(absPath(conf.CertificateAuthority.Local.CertFile, dir))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	block, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	b, err = os.ReadFile(absPath(conf.CertificateAuthority.Local.KeyFile, dir))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	block, _ = pem.Decode(b)
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	_, err = os.Stat(absPath(conf.AccessProxy.HTTP.Certificate.CertFile, dir))
	certFileExist = !os.IsNotExist(err)
	_, err = os.Stat(absPath(conf.AccessProxy.HTTP.Certificate.KeyFile, dir))
	keyFileExist = !os.IsNotExist(err)
	if !certFileExist && !keyFileExist {
		if err := createNewServerCertificate(conf, dir, c, privateKey); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	_, err = os.Stat(absPath(conf.AccessProxy.Credential.SigningPrivateKeyFile, dir))
	if os.IsNotExist(err) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		b, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if err := cert.PemEncode(absPath(conf.AccessProxy.Credential.SigningPrivateKeyFile, dir), "EC PRIVATE KEY", b, nil); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	_, err = os.Stat(absPath(conf.AccessProxy.Credential.InternalTokenFile, dir))
	if os.IsNotExist(err) {
		b := make([]byte, 32)
		for i := range b {
			b[i] = letters[mrand.Intn(len(letters))]
		}
		f, err := os.Create(absPath(conf.AccessProxy.Credential.InternalTokenFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		f.Write(b)
		f.Close()
	}

	_, err = os.Stat(absPath(conf.AccessProxy.Credential.GithubWebHookSecretFile, dir))
	if os.IsNotExist(err) {
		b := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return xerrors.Errorf(": %v", err)
		}
		f, err := os.Create(absPath(conf.AccessProxy.Credential.GithubWebHookSecretFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		f.Write(b)
		f.Close()
	}

	_, err = os.Stat(absPath(conf.AccessProxy.HTTP.Session.KeyFile, dir))
	if os.IsNotExist(err) {
		switch conf.AccessProxy.HTTP.Session.Type {
		case configv2.SessionTypeSecureCookie:
			hashKey := securecookie.GenerateRandomKey(32)
			blockKey := securecookie.GenerateRandomKey(16)
			f, err := os.Create(absPath(conf.AccessProxy.HTTP.Session.KeyFile, dir))
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

func generateNewCertificateAuthority(conf *configv2.Config, dir string) error {
	c, privateKey, err := cert.CreateCertificateAuthorityForConfig(conf)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	b, err := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if err := cert.PemEncode(absPath(conf.CertificateAuthority.Local.KeyFile, dir), "EC PRIVATE KEY", b, nil); err != nil {
		return xerrors.Errorf(": %v", err)
	}

	if err := cert.PemEncode(absPath(conf.CertificateAuthority.Local.CertFile, dir), "CERTIFICATE", c.Raw, nil); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	return nil
}

func createNewServerCertificate(conf *configv2.Config, dir string, ca *x509.Certificate, caPrivateKey crypto.PrivateKey) error {
	c, privateKey, err := cert.GenerateServerCertificate(ca, caPrivateKey, []string{"local-proxy.f110.dev", "*.local-proxy.f110.dev", "short.f110.dev"})

	b, err := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if err := cert.PemEncode(absPath(conf.AccessProxy.HTTP.Certificate.KeyFile, dir), "EC PRIVATE KEY", b, nil); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if err := cert.PemEncode(absPath(conf.AccessProxy.HTTP.Certificate.CertFile, dir), "CERTIFICATE", c.Raw, nil); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	return nil
}

func Bootstrap(rootCmd *cmd.Command) {
	confFile := ""
	bs := &cmd.Command{
		Use:   "bootstrap",
		Short: "Create some config files and secrets for development",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			return bootstrap(confFile)
		},
	}
	bs.Flags().String("config", "Config file").Var(&confFile).Shorthand("c")

	rootCmd.AddCommand(bs)
}
