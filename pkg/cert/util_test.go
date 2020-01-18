package cert

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
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
