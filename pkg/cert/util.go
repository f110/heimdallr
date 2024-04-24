package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math"
	"math/big"
	"net"
	"os"
	"time"

	"go.f110.dev/xerrors"
	"software.sslmate.com/src/go-pkcs12"

	"go.f110.dev/heimdallr/pkg/config/configv2"
)

const (
	CertificateExpirationYear = 10 // year
)

func CreateNewCertificateForClient(name pkix.Name, serial *big.Int, keyType string, keyBits int, password string, ca *configv2.CertificateAuthority) ([]byte, *x509.Certificate, error) {
	now := time.Now()
	cert := &x509.Certificate{
		SerialNumber: serial,
		Subject:      name,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		NotBefore:    now,
		NotAfter:     now.AddDate(CertificateExpirationYear, 0, 0),
	}
	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey
	switch keyType {
	case "ecdsa":
		var c elliptic.Curve
		switch keyBits {
		case 224:
			c = elliptic.P224()
		case 256:
			c = elliptic.P256()
		case 384:
			c = elliptic.P384()
		case 521:
			c = elliptic.P521()
		default:
			return nil, nil, xerrors.New("cert: Unsupported key bits of ECDSA")
		}

		key, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			return nil, nil, xerrors.WithStack(err)
		}
		privateKey = key
		publicKey = key.Public()
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, keyBits)
		if err != nil {
			return nil, nil, xerrors.WithStack(err)
		}
		privateKey = key
		publicKey = key.Public()
	}

	b, err := x509.CreateCertificate(rand.Reader, cert, ca.Certificate, publicKey, ca.Local.PrivateKey)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}

	clientCert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}

	data, err := pkcs12.Encode(rand.Reader, privateKey, clientCert, []*x509.Certificate{ca.Certificate}, password)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}

	return data, clientCert, nil
}

func CreatePrivateKeyAndCertificateRequest(subject pkix.Name, dnsName []string) ([]byte, *ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}

	csr, err := CreateCertificateRequest(subject, dnsName, privateKey)
	if err != nil {
		return nil, nil, err
	}

	return csr, privateKey, nil
}

// CreateCertificateRequest creates CertificateSigningRequest with PrivateKey.
// The return value is pem-encoded CertificateSigningRequest
func CreateCertificateRequest(subject pkix.Name, dnsName []string, privateKey crypto.PrivateKey) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject:  subject,
		DNSNames: dnsName,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}); err != nil {
		return nil, xerrors.WithStack(err)
	}

	return buf.Bytes(), nil
}

func SigningCertificateRequest(r *x509.CertificateRequest, ca *configv2.CertificateAuthority) (*x509.Certificate, error) {
	serialNumber, err := NewSerialNumber()
	if err != nil {
		return nil, err
	}
	n := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      r.Subject,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(CertificateExpirationYear, 0, 0),
	}
	cert, err := x509.CreateCertificate(rand.Reader, n, ca.Certificate, r.PublicKey, ca.Local.PrivateKey)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	c, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	return c, nil
}

func NewSerialNumber() (*big.Int, error) {
	if s, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64)); err != nil {
		return nil, xerrors.WithStack(err)
	} else {
		return s, nil
	}
}

// GenerateServerCertificate will generate a certificate and a private key for server auth.
// Generated private key is ecdsa 256-bit.
// The expiration of the certificate is 1 year.
func GenerateServerCertificate(ca *x509.Certificate, caPrivateKey crypto.PrivateKey, dnsNames []string) (*x509.Certificate, crypto.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
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
	certByte, err := x509.CreateCertificate(rand.Reader, template, ca, &privKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}
	cert, err := x509.ParseCertificate(certByte)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}

	return cert, privKey, nil
}

// GenerateMutualTLSCertificate will generate a certificate and a private key for server and client auth.
func GenerateMutualTLSCertificate(ca *x509.Certificate, caPrivateKey crypto.PrivateKey, dnsNames []string, ips []string) (*x509.Certificate, crypto.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}

	ipAddresses := make([]net.IP, 0)
	if len(ips) > 0 {
		for _, v := range ips {
			ipAddresses = append(ipAddresses, net.ParseIP(v))
		}
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
		IPAddresses:           ipAddresses,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	certByte, err := x509.CreateCertificate(rand.Reader, template, ca, &privKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}
	cert, err := x509.ParseCertificate(certByte)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}

	return cert, privKey, nil
}

func CreateCertificateAuthorityForConfig(conf *configv2.Config) (*x509.Certificate, crypto.PrivateKey, error) {
	return CreateCertificateAuthority(
		"Heimdallr CA",
		conf.CertificateAuthority.Local.Organization,
		conf.CertificateAuthority.Local.OrganizationUnit,
		conf.CertificateAuthority.Local.Country,
		"ecdsa",
	)
}

func CreateCertificateAuthority(commonName, org, orgUnit, country, keyType string) (*x509.Certificate, crypto.PrivateKey, error) {
	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey
	switch keyType {
	case "ecdsa":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, xerrors.WithStack(err)
		}
		privateKey = key
		publicKey = &key.PublicKey
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, xerrors.WithStack(err)
		}
		privateKey = key
		publicKey = &key.PublicKey
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
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
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(rand.Reader, ca, ca, publicKey, privateKey)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}
	caCert, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}

	return caCert, privateKey, nil
}

func PemEncode(path, typ string, b []byte, headers map[string]string) error {
	pemFile, err := os.Create(path)
	if err != nil {
		return xerrors.WithStack(err)
	}
	if err := pem.Encode(pemFile, &pem.Block{Type: typ, Bytes: b, Headers: headers}); err != nil {
		_ = os.Remove(pemFile.Name())
		return xerrors.WithStack(err)
	}
	return xerrors.WithStack(pemFile.Close())
}
