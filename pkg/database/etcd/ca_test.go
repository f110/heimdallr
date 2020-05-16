package etcd

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

	"software.sslmate.com/src/go-pkcs12"

	"github.com/f110/lagrangian-proxy/pkg/cert"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/connector"
	"github.com/f110/lagrangian-proxy/pkg/database"
)

func newCertificateAuthorityConfig(t *testing.T) *config.CertificateAuthority {
	caCert, caPrivateKey, err := cert.CreateCertificateAuthority("for test", "test", "", "jp")
	if err != nil {
		t.Fatal(err)
	}
	cp := x509.NewCertPool()
	cp.AddCert(caCert)

	return &config.CertificateAuthority{Certificate: caCert, PrivateKey: caPrivateKey, CertPool: cp}
}

func TestNewCA(t *testing.T) {
	ca, err := NewCA(context.Background(), newCertificateAuthorityConfig(t), client)
	if err != nil {
		t.Fatal(err)
	}
	if ca == nil {
		t.Fatal("NewCA should return a value")
	}

	_, err = ca.NewAgentCertificate(context.Background(), "test", "for testing")
	if err != nil {
		t.Fatal(err)
	}
	signedCerts, err := ca.GetSignedCertificates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range signedCerts {
		if err := ca.Revoke(context.Background(), v); err != nil {
			t.Fatal(err)
		}
	}

	newCA, err := NewCA(context.Background(), newCertificateAuthorityConfig(t), client)
	if err != nil {
		t.Fatal(err)
	}
	if newCA == nil {
		t.Fatal("NewCA should return a value")
	}

	clearDatabase(t)
}

func TestCA_NewAgentCertificate(t *testing.T) {
	ca, err := NewCA(context.Background(), newCertificateAuthorityConfig(t), client)
	if err != nil {
		t.Fatal(err)
	}

	data, err := ca.NewAgentCertificate(context.Background(), "test", "for testing")
	if err != nil {
		t.Fatal(err)
	}

	privateKey, clientCert, _, err := pkcs12.DecodeChain(data.P12, connector.DefaultCertificatePassword)
	if err != nil {
		t.Fatal(err)
	}
	switch privateKey.(type) {
	case *ecdsa.PrivateKey:
	default:
		t.Fatal("Unexpected private key algorithm")
	}

	signedCerts, err := ca.GetSignedCertificates(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(signedCerts) != 1 {
		t.Fatalf("Expect to get 1 cert but %d", len(signedCerts))
	}

	signedCert, err := ca.GetSignedCertificate(context.Background(), clientCert.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	if signedCert.Comment != "for testing" {
		t.Fatal("Success creating and getting certificate but unexpected result")
	}

	clearDatabase(t)
}

func TestCA_NewClientCertificate(t *testing.T) {
	ca, err := NewCA(context.Background(), newCertificateAuthorityConfig(t), client)
	if err != nil {
		t.Fatal(err)
	}

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
	if err != nil {
		t.Fatal(err)
	}

	privateKey, clientCert, _, err := pkcs12.DecodeChain(data.P12, "test")
	if err != nil {
		t.Fatal(err)
	}
	switch privateKey.(type) {
	case *rsa.PrivateKey:
	default:
		t.Fatal("Unexpected private key algorithm")
	}

	signedCert, err := ca.GetSignedCertificate(context.Background(), clientCert.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}

	if signedCert.Certificate.Subject.CommonName != "test@example.com" {
		t.Errorf("Unexpected common name: %s", signedCert.Certificate.Subject.CommonName)
	}

	if err := ca.Revoke(context.Background(), signedCert); err != nil {
		t.Fatal(err)
	}

	select {
	case revoked := <-revokedCertEventCh:
		if revoked.CommonName != "test@example.com" {
			t.Fatalf("Got a revoked cert but unexpected common name: %s", revoked.CommonName)
		}
	case <-time.After(time.Second):
		t.Fatal("Expect getting a revoked cert via watch channel")
	}

	revokedCerts := ca.GetRevokedCertificates()
	if len(revokedCerts) != 1 {
		t.Fatalf("Expect 1 revoked cert %d got", len(revokedCerts))
	}
	if revokedCerts[0].CommonName != "test@example.com" {
		t.Fatalf("Got a revoked cert but unexpected common name: %s", revokedCerts[0].CommonName)
	}

	clearDatabase(t)
}

func TestCA_NewServerCertificate(t *testing.T) {
	ca, err := NewCA(context.Background(), newCertificateAuthorityConfig(t), client)
	if err != nil {
		t.Fatal(err)
	}

	c, _, err := ca.NewServerCertificate("test.example.com")
	if err != nil {
		t.Fatal(err)
	}

	if c.Subject.CommonName != "test.example.com" {
		t.Fatalf("Unexpected common name: %s", c.Subject.CommonName)
	}

	clearDatabase(t)
}

func TestCA_SignCertificateRequest(t *testing.T) {
	ca, err := NewCA(context.Background(), newCertificateAuthorityConfig(t), client)
	if err != nil {
		t.Fatal(err)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "test@example.com"},
		DNSNames: []string{},
	}
	b, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(b)
	if err != nil {
		t.Fatal(err)
	}

	c, err := ca.SignCertificateRequest(context.Background(), csr, "for testing", false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Certificate.Subject.CommonName != "test@example.com" {
		t.Fatalf("Unexpected common name: %s", c.Certificate.Subject.CommonName)
	}

	clearDatabase(t)
}
