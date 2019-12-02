package auth

import (
	"context"
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
	"github.com/f110/lagrangian-proxy/pkg/database/etcd"
	"golang.org/x/xerrors"
)

type CertificateAuthority struct {
	store *etcd.CA
}

func (ca *CertificateAuthority) NewClientCertificate(ctx context.Context, name, password, comment string) ([]byte, error) {
	return ca.store.NewClientCertificate(ctx, name, password, comment)
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

func GenerateServerCertificate(ca *x509.Certificate, caPrivateKey crypto.PrivateKey, serialNumber int64, dnsNames []string) ([]byte, crypto.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			Organization:       []string{"test"},
			OrganizationalUnit: []string{"dev"},
			Country:            []string{"jp"},
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

func PemEncode(path, typ string, b []byte) error {
	pemFile, err := os.Create(path)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if err := pem.Encode(pemFile, &pem.Block{Type: typ, Bytes: b}); err != nil {
		_ = os.Remove(pemFile.Name())
		return xerrors.Errorf(": %v", err)
	}
	return pemFile.Close()
}
