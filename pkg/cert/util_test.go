package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"testing"

	"github.com/f110/lagrangian-proxy/pkg/config"
)

func TestSigningCertificateRequest(t *testing.T) {
	cases := []struct {
		File       string
		CommonName string
	}{
		{
			File:       "testdata/csr_1.pem",
			CommonName: "fmhrit@gmail.com",
		},
	}

	caCertByte, caPrivateKey, err := CreateCertificateAuthority("test", "test", "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertByte)
	if err != nil {
		t.Fatal(err)
	}
	ca := &config.CertificateAuthority{
		Certificate: caCert,
		PrivateKey:  caPrivateKey,
	}

	for _, c := range cases {
		b, err := ioutil.ReadFile(c.File)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			t.Fatal("testdata is not a pem format")
		}
		if block.Type != "CERTIFICATE REQUEST" {
			t.Fatal("testdata is not a CSR")
		}

		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}

		signedCert, err := SigningCertificateRequest(csr, ca)
		if err != nil {
			t.Fatal(err)
		}
		if signedCert.Subject.CommonName != c.CommonName {
			t.Errorf("CommonName of Subject is not %s: %s", c.CommonName, signedCert.Subject.CommonName)
		}
		if signedCert.Issuer.CommonName != "test" {
			t.Errorf("CommonName of Issuer is not %s: %s", "test", signedCert.Issuer.CommonName)
		}
	}
}

func TestPemEncode(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		f, err := ioutil.TempFile("", "")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())

		privateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		b, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := PemEncode(f.Name(), "EC PRIVATE KEY", b, nil); err != nil {
			t.Fatal(err)
		}

		readed, err := ioutil.ReadFile(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		block, rest := pem.Decode(readed)
		if block == nil {
			t.Fatal("failed decoding pem file")
		}
		if len(rest) != 0 {
			t.Fatal("probably failed encoding pem file. found some trailing bytes which unexpected")
		}
		if block.Type != "EC PRIVATE KEY" {
			t.Fatalf("expected block type is EC PRIVATE KEY: %s", block.Type)
		}
	})

	t.Run("illegal header", func(t *testing.T) {
		f, err := ioutil.TempFile("", "")
		if err != nil {
			t.Fatal(err)
		}

		err = PemEncode(f.Name(), "ILLEGAL HEADER:", []byte("illegal"), map[string]string{"illegal: ": "value"})
		if err == nil {
			t.Fatal("returns err is expected but not")
		}

		if _, err := os.Stat(f.Name()); !os.IsNotExist(err) {
			t.Fatal("if can not encode to pem, should delete a temporary file but not deleted")
		}
	})
}
