package userconfig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/cert"
)

const (
	Directory = ".heimdallr"

	TokenFilename       = "token"
	CertificateFilename = "client.crt"
	PrivateKeyFilename  = "client.key"
	CSRFilename         = "client.csr"
)

type UserDir struct {
	home string
}

func New() (*UserDir, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return &UserDir{home: home}, nil
}

func (u *UserDir) GetToken() (string, error) {
	b, err := u.readFile(TokenFilename)
	if err != nil {
		return "", xerrors.Errorf(": %w", err)
	}

	return string(b), nil
}

func (u *UserDir) SetToken(token string) error {
	if err := u.writeFile(TokenFilename, []byte(token), 0600); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (u *UserDir) GetPrivateKey() (crypto.PrivateKey, error) {
	if _, err := os.Stat(filepath.Join(u.home, Directory, PrivateKeyFilename)); os.IsNotExist(err) {
		if err := u.newPrivateKey(); err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
	}

	buf, err := u.readFile(PrivateKeyFilename)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	b, rest := pem.Decode(buf)
	if len(rest) > 0 {
		return nil, xerrors.New("unexpected private key file. Please re-create the private key.")
	}
	if b.Type != "EC PRIVATE KEY" {
		return nil, xerrors.New("unexpected private key file")
	}

	key, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return key, nil
}

func (u *UserDir) GetCertificate() (*tls.Certificate, error) {
	c, err := u.getCertificate()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	privateKey, err := u.GetPrivateKey()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{c.Raw},
		PrivateKey:  privateKey,
	}
	return tlsCert, nil
}

func (u *UserDir) GetCSR() ([]byte, error) {
	privateKey, err := u.GetPrivateKey()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	csr, err := cert.CreateCertificateRequest(pkix.Name{}, nil, privateKey)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if err := u.writeFile(CSRFilename, csr, 0644); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return csr, nil
}

func (u *UserDir) SetCertificate(c *x509.Certificate) error {
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := u.writeFile(CertificateFilename, buf.Bytes(), 0600); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (u *UserDir) getCertificate() (*x509.Certificate, error) {
	buf, err := u.readFile(CertificateFilename)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if buf == nil {
		return nil, os.ErrNotExist
	}

	b, rest := pem.Decode(buf)
	if len(rest) > 0 {
		return nil, xerrors.New("unexpected certificate key file")
	}
	if b == nil {
		return nil, xerrors.Errorf("certificate file is not encoded pem")
	}
	if b.Type != "CERTIFICATE" {
		return nil, xerrors.Errorf("unexpected certificate type: %s", b.Type)
	}

	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return c, nil
}

func (u *UserDir) newPrivateKey() error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	der, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := u.writeFile(PrivateKeyFilename, buf.Bytes(), 0400); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (u *UserDir) readFile(filename string) ([]byte, error) {
	f, err := os.Open(filepath.Join(u.home, Directory, filename))
	if os.IsNotExist(err) {
		return nil, nil
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return b, nil
}

func (u *UserDir) writeFile(filename string, content []byte, umask os.FileMode) error {
	_, err := os.Stat(filepath.Join(u.home, Directory))
	if os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Join(u.home, Directory), 0700); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}
	f, err := os.Create(filepath.Join(u.home, Directory, filename))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	_, err = f.Write(content)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := f.Chmod(umask); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := f.Close(); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}
