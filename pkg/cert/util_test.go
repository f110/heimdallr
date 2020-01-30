package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"os"
	"testing"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
)

func createCAForTest(t *testing.T) *config.CertificateAuthority {
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

	return ca
}

func TestCreateNewCertificateForClient(t *testing.T) {
	ca := createCAForTest(t)

	t.Run("Default", func(t *testing.T) {
		t.Parallel()

		serial, err := NewSerialNumber()
		if err != nil {
			t.Fatal(err)
		}

		p12, _, err := CreateNewCertificateForClient(pkix.Name{CommonName: "test@f110.dev"}, serial, database.DefaultPrivateKeyType, database.DefaultPrivateKeyBits, "test", ca)
		if err != nil {
			t.Fatalf("%+v", err)
		}

		_, cert, _, err := pkcs12.DecodeChain(p12, "test")
		if err != nil {
			t.Fatal(err)
		}
		if cert.Subject.CommonName != "test@f110.dev" {
			t.Errorf("CommonName is test@f110.dev: %s", cert.Subject.CommonName)
		}
	})

	t.Run("RSA", func(t *testing.T) {
		t.Parallel()

		serial, err := NewSerialNumber()
		if err != nil {
			t.Fatal(err)
		}

		p12, _, err := CreateNewCertificateForClient(pkix.Name{CommonName: "test@f110.dev"}, serial, "rsa", 4096, "test", ca)
		if err != nil {
			t.Fatalf("%+v", err)
		}

		privateKey, _, _, err := pkcs12.DecodeChain(p12, "test")
		if err != nil {
			t.Fatal(err)
		}

		switch v := privateKey.(type) {
		case *rsa.PrivateKey:
		default:
			t.Errorf("Unexpected private key type: %v", v)
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		bits := []int{224, 256, 384, 521}

		serial, err := NewSerialNumber()
		if err != nil {
			t.Fatal(err)
		}

		for _, b := range bits {
			p12, _, err := CreateNewCertificateForClient(pkix.Name{CommonName: "test@f110.dev"}, serial, "ecdsa", b, "test", ca)
			if err != nil {
				t.Fatalf("%+v", err)
			}

			privateKey, _, _, err := pkcs12.DecodeChain(p12, "test")
			if err != nil {
				t.Fatal(err)
			}

			switch v := privateKey.(type) {
			case *ecdsa.PrivateKey:
				if v.Params().BitSize != b {
					t.Errorf("private key type is expected but key bits is expected size: %d", v.Params().BitSize)
				}
			default:
				t.Errorf("Unexpected private key type: %v", v)
			}
		}
	})
}

func TestCreateCertificateAuthorityForConfig(t *testing.T) {
	_, _, err := CreateCertificateAuthorityForConfig(&config.Config{
		General: &config.General{
			CertificateAuthority: &config.CertificateAuthority{
				Organization:     "test",
				OrganizationUnit: "test",
				Country:          "jp",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

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

	ca := createCAForTest(t)

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

func TestGenerateServerCertificate(t *testing.T) {
	ca := createCAForTest(t)
	certByte, privateKey, err := GenerateServerCertificate(ca.Certificate, ca.PrivateKey, []string{"test-server.test.f110.dev", "internal.test.f110.dev"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certByte)
	if err != nil {
		t.Fatal(err)
	}

	if privateKey == nil {
		t.Error("was not generate a private key")
	}
	if cert.Subject.CommonName != "test-server.test.f110.dev" {
		t.Errorf("CommonName is test-server.test.f110.dev: %s", cert.Subject.CommonName)
	}
}

func TestCreateCertificateRequest(t *testing.T) {
	csrByte, privateKey, err := CreateCertificateRequest(pkix.Name{CommonName: "test@f110.dev"}, []string{""})
	if err != nil {
		t.Fatal(err)
	}

	if privateKey == nil {
		t.Error("was not generate a private key")
	}
	block, _ := pem.Decode(csrByte)
	if block == nil {
		t.Fatal("CreateCertificateRequest was not returned pem encoded CSR")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("CreateCertificateRequest was returned pem bytes but not CERTIFICATE REQUEST: %s", block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "test@f110.dev" {
		t.Errorf("CommonName is test@f110.dev: %s", csr.Subject.CommonName)
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

	t.Run("Illegal header", func(t *testing.T) {
		f, err := ioutil.TempFile("", "")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(f.Name())

		err = PemEncode(f.Name(), "ILLEGAL HEADER:", []byte("illegal"), map[string]string{"illegal: ": "value"})
		if err == nil {
			t.Fatal("returns err is expected but not")
		}

		if _, err := os.Stat(f.Name()); !os.IsNotExist(err) {
			t.Fatal("if can not encode to pem, should delete a temporary file but not deleted")
		}
	})

	t.Run("Failed create file", func(t *testing.T) {
		err := PemEncode("/unknown/notexist/file/path", "UNKNOWN PATH", []byte("illegal"), nil)
		if err == nil {
			t.Fatal("PemEncode is success but is not expect")
		}
	})
}
