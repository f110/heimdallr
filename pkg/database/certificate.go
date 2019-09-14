package database

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"golang.org/x/xerrors"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	CertificateExpiration = 10 // year
)

type CertificateAuthority interface {
	GetSignedCertificates(ctx context.Context) ([]*SignedCertificate, error)
	GetSignedCertificate(ctx context.Context, serial *big.Int) (*SignedCertificate, error)
	GetRevokedCertificates(ctx context.Context) ([]*RevokedCertificate, error)
	NewClientCertificate(ctx context.Context, name, password, comment string) ([]byte, error)
	Revoke(ctx context.Context, certificate *SignedCertificate) error
}

type SignedCertificate struct {
	Certificate *x509.Certificate
	P12         []byte
	IssuedAt    time.Time
	Comment     string
}

type RevokedCertificate struct {
	CommonName   string
	SerialNumber *big.Int
	IssuedAt     time.Time
	RevokedAt    time.Time
	Comment      string
}

func CreateNewCertificateForClient(name pkix.Name, serial *big.Int, password string, ca *config.CertificateAuthority) ([]byte, *x509.Certificate, error) {
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: serial,
		Subject:      name,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		NotBefore:    now,
		NotAfter:     now.AddDate(CertificateExpiration, 0, 0),
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %v", err)
	}
	b, err := x509.CreateCertificate(rand.Reader, cert, ca.Certificate, &privateKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %v", err)
	}

	clientCert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %v", err)
	}

	data, err := pkcs12.Encode(rand.Reader, privateKey, clientCert, []*x509.Certificate{ca.Certificate}, password)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %v", err)
	}

	return data, clientCert, nil
}
