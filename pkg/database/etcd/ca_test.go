package etcd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	"github.com/f110/lagrangian-proxy/pkg/cert"
	"github.com/f110/lagrangian-proxy/pkg/database"
)

func newCertificate(t *testing.T) *x509.Certificate {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	serial, err := cert.NewSerialNumber()
	if err != nil {
		t.Fatal(err)
	}
	v := &x509.Certificate{SerialNumber: serial}
	newCertBuf, err := x509.CreateCertificate(rand.Reader, v, v, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	newCert, err := x509.ParseCertificate(newCertBuf)
	if err != nil {
		t.Fatal(err)
	}

	return newCert
}

func TestNewCA(t *testing.T) {
	ca, err := NewCA(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if ca == nil {
		t.Fatal("NewCA should return a value")
	}
}

func TestCA(t *testing.T) {
	ca, err := NewCA(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}

	err = ca.SetSignedCertificate(context.Background(), &database.SignedCertificate{
		Certificate: newCertificate(t),
		IssuedAt:    time.Now(),
		Comment:     "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = ca.SetSignedCertificate(context.Background(), &database.SignedCertificate{
		Certificate: newCertificate(t),
		IssuedAt:    time.Now(),
		Comment:     "test 2",
	})
	if err != nil {
		t.Fatal(err)
	}
	certs, err := ca.GetSignedCertificate(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 {
		t.Errorf("Expect 2 certificates: got %d certificates", len(certs))
	}
	firstCert, err := ca.GetSignedCertificate(context.Background(), certs[0].Certificate.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstCert) != 1 {
		t.Fatalf("Expect to return 1 certificate: got %d certificates", len(firstCert))
	}
	if firstCert[0].Certificate.SerialNumber.Cmp(certs[0].Certificate.SerialNumber) != 0 {
		t.Fatalf("got unexpected a certificate: %v", firstCert[0])
	}

	err = ca.SetRevokedCertificate(context.Background(), &database.RevokedCertificate{
		SerialNumber: certs[0].Certificate.SerialNumber,
	})
	if err != nil {
		t.Fatal(err)
	}
	revokes, err := ca.GetRevokedCertificate(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(revokes) != 1 {
		t.Fatalf("Expect to return 1 certificate: got %d certificates", len(revokes))
	}

	clearDatabase(t)
}

func TestCA_NewSerialNumber(t *testing.T) {
	ca, err := NewCA(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}

	serial, err := ca.NewSerialNumber(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	newSerial, err := ca.NewSerialNumber(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if serial.Cmp(newSerial) == 0 {
		t.Error("Should generate different a number")
	}

	clearDatabase(t)
}
