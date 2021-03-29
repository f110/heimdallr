package etcd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/database"
)

func newCertificate(t *testing.T) *x509.Certificate {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serial, err := cert.NewSerialNumber()
	require.NoError(t, err)
	v := &x509.Certificate{SerialNumber: serial}
	newCertBuf, err := x509.CreateCertificate(rand.Reader, v, v, privateKey.Public(), privateKey)
	require.NoError(t, err)

	newCert, err := x509.ParseCertificate(newCertBuf)
	require.NoError(t, err)

	return newCert
}

func TestNewCA(t *testing.T) {
	ca := NewCA(client)
	defer ca.Close()
	assert.NotNil(t, ca)
}

func TestCA(t *testing.T) {
	ca := NewCA(client)
	defer ca.Close()

	err := ca.SetSignedCertificate(context.Background(), &database.SignedCertificate{
		Certificate: newCertificate(t),
		IssuedAt:    time.Now(),
		Comment:     "test",
	})
	require.NoError(t, err)
	err = ca.SetSignedCertificate(context.Background(), &database.SignedCertificate{
		Certificate: newCertificate(t),
		IssuedAt:    time.Now(),
		Comment:     "test 2",
	})
	require.NoError(t, err)
	certs, err := ca.GetSignedCertificate(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, certs, 2)
	firstCert, err := ca.GetSignedCertificate(context.Background(), certs[0].Certificate.SerialNumber)
	require.NoError(t, err)
	require.Len(t, firstCert, 1)
	assert.Equal(t, certs[0].Certificate.SerialNumber, firstCert[0].Certificate.SerialNumber)

	err = ca.SetRevokedCertificate(context.Background(), &database.RevokedCertificate{
		SerialNumber: certs[0].Certificate.SerialNumber,
	})
	require.NoError(t, err)
	revokes, err := ca.GetRevokedCertificate(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, revokes, 1)
}

func TestCA_NewSerialNumber(t *testing.T) {
	ca := NewCA(client)
	defer ca.Close()

	serial, err := ca.NewSerialNumber(context.Background())
	require.NoError(t, err)
	newSerial, err := ca.NewSerialNumber(context.Background())
	require.NoError(t, err)
	assert.NotEqual(t, serial, newSerial)
}
