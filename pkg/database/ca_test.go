package database_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/database/memory"
)

func TestMarshal(t *testing.T) {
	caCert, caPrivateKey, err := cert.CreateCertificateAuthority("for testing", "test", "", "jp", "ecdsa")
	require.NoError(t, err)
	cp := x509.NewCertPool()
	cp.AddCert(caCert)

	caConfig := &configv2.CertificateAuthority{
		Local: &configv2.CertificateAuthorityLocal{
			PrivateKey: caPrivateKey,
		},
		Certificate: caCert,
		CertPool:    cp,
	}
	ca, err := cert.NewCertificateAuthority(memory.NewCA(), caConfig)
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "test@example.com"},
		DNSNames: []string{},
	}
	b, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(b)
	require.NoError(t, err)
	c, err := ca.SignCertificateRequest(context.Background(), csr, "for testing", false, false)
	require.NoError(t, err)

	c.Certificate.PublicKey = nil
	buf, err := c.Marshal()
	require.NoError(t, err)

	parsed, err := database.ParseSignedCertificate(buf)
	require.NoError(t, err)
	assert.Equal(t, c.Certificate.Subject, parsed.Certificate.Subject)
}

func TestParseSignedCertificate(t *testing.T) {
	// The testdata contains the public key in *x509.Certificate.
	buf, err := os.ReadFile("testdata/signed_certificate_118.dat")
	require.NoError(t, err)

	signedCertificate, err := database.ParseSignedCertificate(buf)
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", signedCertificate.Certificate.Subject.CommonName)
	assert.Equal(t, int64(6734327822506238185), signedCertificate.Certificate.SerialNumber.Int64())
}
