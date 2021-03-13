package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/database/memory"
)

func newCertificateAuthorityConfig(t *testing.T) *configv2.CertificateAuthority {
	caCert, caPrivateKey, err := CreateCertificateAuthority("for test", "test", "", "jp", "ecdsa")
	if err != nil {
		t.Fatal(err)
	}
	cp := x509.NewCertPool()
	cp.AddCert(caCert)

	return &configv2.CertificateAuthority{
		Local: &configv2.CertificateAuthorityLocal{
			PrivateKey: caPrivateKey,
		},
		Certificate: caCert,
		CertPool:    cp,
	}
}

func TestCertificateAuthority_NewClientCertificate(t *testing.T) {
	ca, err := NewCertificateAuthority(memory.NewCA(), newCertificateAuthorityConfig(t))
	require.NoError(t, err)

	doneCh := make(chan struct{})
	revokedCertEventCh := make(chan *database.RevokedCertificate, 1)
	watchCh := ca.WatchRevokeCertificate()
	go func() {
		close(doneCh)
		v := <-watchCh
		revokedCertEventCh <- v
	}()
	<-doneCh

	data, err := ca.NewClientCertificate(
		context.Background(),
		"test@example.com",
		"rsa",
		2048,
		"test",
		"for testing",
	)
	require.NoError(t, err)

	privateKey, clientCert, _, err := pkcs12.DecodeChain(data.P12, "test")
	require.NoError(t, err)
	switch privateKey.(type) {
	case *rsa.PrivateKey:
	default:
		require.Fail(t, "Unexpected private key algorithm")
	}

	signedCert, err := ca.GetSignedCertificate(context.Background(), clientCert.SerialNumber)
	require.NoError(t, err)

	assert.Equal(t, "test@example.com", signedCert.Certificate.Subject.CommonName)

	err = ca.Revoke(context.Background(), signedCert)
	require.NoError(t, err)

	select {
	case revoked := <-revokedCertEventCh:
		require.Equal(t, "test@example.com", revoked.CommonName)
	case <-time.After(time.Second):
		require.Fail(t, "Expect getting a revoked cert via watch channel")
	}

	revokedCerts, err := ca.GetRevokedCertificates(context.Background())
	require.NoError(t, err)
	require.Len(t, revokedCerts, 1)
	assert.Equal(t, "test@example.com", revokedCerts[0].CommonName)
}

func TestCertificateAuthority_NewAgentCertificate(t *testing.T) {
	ca, err := NewCertificateAuthority(memory.NewCA(), newCertificateAuthorityConfig(t))
	require.NoError(t, err)

	data, err := ca.NewAgentCertificate(context.Background(), "test", "defaultpassword", "for testing")
	require.NoError(t, err)

	privateKey, clientCert, _, err := pkcs12.DecodeChain(data.P12, "defaultpassword")
	require.NoError(t, err)
	switch privateKey.(type) {
	case *ecdsa.PrivateKey:
	default:
		require.Fail(t, "Unexpected private key algorithm")
	}

	signedCerts, err := ca.GetSignedCertificates(context.Background())
	require.NoError(t, err)
	require.Len(t, signedCerts, 1)

	signedCert, err := ca.GetSignedCertificate(context.Background(), clientCert.SerialNumber)
	require.NoError(t, err)
	assert.Equal(t, "for testing", signedCert.Comment)
}

func TestCertificateAuthority_NewServerCertificate(t *testing.T) {
	ca, err := NewCertificateAuthority(memory.NewCA(), newCertificateAuthorityConfig(t))
	require.NoError(t, err)

	c, _, err := ca.NewServerCertificate("test.example.com")
	require.NoError(t, err)

	assert.Equal(t, "test.example.com", c.Subject.CommonName)
}

func TestCertificateAuthority_SignCertificateRequest(t *testing.T) {
	ca, err := NewCertificateAuthority(memory.NewCA(), newCertificateAuthorityConfig(t))
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
	assert.Equal(t, "test@example.com", c.Certificate.Subject.CommonName)
}
