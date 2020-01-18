package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math"
	"math/big"
	"os"
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

func CreateCertificateRequest(subject pkix.Name, dnsName []string) ([]byte, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %v", err)
	}

	template := &x509.CertificateRequest{
		Subject:  subject,
		DNSNames: dnsName,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %v", err)
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}); err != nil {
		return nil, nil, xerrors.Errorf(": %v", err)
	}

	return buf.Bytes(), privateKey, nil
}

func SigningCertificateRequest(r *x509.CertificateRequest, ca *config.CertificateAuthority) (*x509.Certificate, error) {
	serialNumber, err := NewSerialNumber()
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	n := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      r.Subject,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(CertificateExpirationYear, 0, 0),
	}
	cert, err := x509.CreateCertificate(rand.Reader, n, ca.Certificate, r.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	c, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	return c, nil
}

func NewSerialNumber() (*big.Int, error) {
	if s, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64)); err != nil {
		return nil, xerrors.Errorf(": %v", err)
	} else {
		return s, nil
	}
}

func GenerateServerCertificate(ca *x509.Certificate, caPrivateKey crypto.PrivateKey, dnsNames []string) ([]byte, crypto.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, nil, xerrors.Errorf(": %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:       ca.Subject.Organization,
			OrganizationalUnit: ca.Subject.OrganizationalUnit,
			Country:            ca.Subject.Country,
			CommonName:         dnsNames[0],
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().AddDate(1, 0, 0).UTC(),
		DNSNames:              dnsNames,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, ca, &privKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %v", err)
	}

	return cert, privKey, nil
}

func CreateCertificateAuthorityForConfig(conf *config.Config) ([]byte, crypto.PrivateKey, error) {
	return CreateCertificateAuthority(
		"Lagrangian Proxy CA",
		conf.General.CertificateAuthority.Organization,
		conf.General.CertificateAuthority.OrganizationUnit,
		conf.General.CertificateAuthority.Country,
	)
}

func CreateCertificateAuthority(commonName, org, orgUnit, country string) ([]byte, crypto.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %v", err)
	}
	publicKey := &privateKey.PublicKey

	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, nil, xerrors.Errorf(": %v", err)
	}
	ca := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:       []string{org},
			OrganizationalUnit: []string{orgUnit},
			Country:            []string{country},
			CommonName:         commonName,
		},
		NotBefore:             time.Now().UTC(),
		NotAfter:              time.Now().AddDate(10, 0, 0).UTC(),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(rand.Reader, ca, ca, publicKey, privateKey)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %v", err)
	}

	return cert, privateKey, nil
}

func PemEncode(path, typ string, b []byte, headers map[string]string) error {
	pemFile, err := os.Create(path)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if err := pem.Encode(pemFile, &pem.Block{Type: typ, Bytes: b, Headers: headers}); err != nil {
		_ = os.Remove(pemFile.Name())
		return xerrors.Errorf(": %v", err)
	}
	return pemFile.Close()
}
