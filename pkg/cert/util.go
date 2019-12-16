package cert

import (
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
	CertificateExpirationYear = 10 // year
)

func CreateNewCertificateForClient(name pkix.Name, serial *big.Int, password string, ca *config.CertificateAuthority) ([]byte, *x509.Certificate, error) {
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: serial,
		Subject:      name,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		NotBefore:    now,
		NotAfter:     now.AddDate(CertificateExpirationYear, 0, 0),
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
