package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
)

func createCAForTest(t *testing.T) *configv2.CertificateAuthority {
	caCert, caPrivateKey, err := CreateCertificateAuthority("test", "test", "test", "test", "ecdsa")
	if err != nil {
		t.Fatal(err)
	}
	ca := &configv2.CertificateAuthority{
		Local: &configv2.CertificateAuthorityLocal{
			PrivateKey: caPrivateKey,
		},
		Certificate: caCert,
	}

	return ca
}

func TestCreateNewCertificateForClient(t *testing.T) {
	ca := createCAForTest(t)

	t.Run("Default", func(t *testing.T) {
		t.Parallel()

		serial, err := NewSerialNumber()
		require.NoError(t, err)

		p12, _, err := CreateNewCertificateForClient(pkix.Name{CommonName: "test@f110.dev"}, serial, database.DefaultPrivateKeyType, database.DefaultPrivateKeyBits, "test", ca)
		require.NoError(t, err)

		_, cert, _, err := pkcs12.DecodeChain(p12, "test")
		require.NoError(t, err)
		assert.Equal(t, "test@f110.dev", cert.Subject.CommonName)
	})

	t.Run("RSA", func(t *testing.T) {
		t.Parallel()

		serial, err := NewSerialNumber()
		require.NoError(t, err)

		p12, _, err := CreateNewCertificateForClient(pkix.Name{CommonName: "test@f110.dev"}, serial, "rsa", 4096, "test", ca)
		require.NoError(t, err)

		privateKey, _, _, err := pkcs12.DecodeChain(p12, "test")
		require.NoError(t, err)

		switch v := privateKey.(type) {
		case *rsa.PrivateKey:
		default:
			require.Fail(t, "Unexpected private key type: %v", v)
		}
	})

	t.Run("ECDSA", func(t *testing.T) {
		bits := []int{224, 256, 384, 521}

		serial, err := NewSerialNumber()
		require.NoError(t, err)

		for _, b := range bits {
			p12, _, err := CreateNewCertificateForClient(pkix.Name{CommonName: "test@f110.dev"}, serial, "ecdsa", b, "test", ca)
			require.NoError(t, err)

			privateKey, _, _, err := pkcs12.DecodeChain(p12, "test")
			require.NoError(t, err)

			switch v := privateKey.(type) {
			case *ecdsa.PrivateKey:
				assert.Equal(t, b, v.Params().BitSize)
			default:
				assert.Fail(t, "Unexpected private key type")
			}
		}
	})
}

func TestCreateCertificateAuthorityForConfig(t *testing.T) {
	_, _, err := CreateCertificateAuthorityForConfig(&configv2.Config{
		CertificateAuthority: &configv2.CertificateAuthority{
			Local: &configv2.CertificateAuthorityLocal{
				Organization:     "test",
				OrganizationUnit: "test",
				Country:          "jp",
			},
		},
	})
	require.NoError(t, err)
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
		b, err := os.ReadFile(c.File)
		require.NoError(t, err)
		block, _ := pem.Decode(b)
		require.NotNil(t, block)
		require.Equal(t, "CERTIFICATE REQUEST", block.Type)

		csr, err := x509.ParseCertificateRequest(block.Bytes)
		require.NoError(t, err)

		signedCert, err := SigningCertificateRequest(csr, ca)
		require.NoError(t, err)
		assert.Equal(t, c.CommonName, signedCert.Subject.CommonName)
		assert.Equal(t, "test", signedCert.Issuer.CommonName)
	}
}

func TestGenerateServerCertificate(t *testing.T) {
	ca := createCAForTest(t)
	serverCert, privateKey, err := GenerateServerCertificate(ca.Certificate, ca.Local.PrivateKey, []string{"test-server.test.f110.dev", "internal.test.f110.dev"})
	require.NoError(t, err)

	assert.NotNil(t, privateKey)
	assert.Equal(t, "test-server.test.f110.dev", serverCert.Subject.CommonName)
}

func TestCreateCertificateRequest(t *testing.T) {
	csrByte, privateKey, err := CreatePrivateKeyAndCertificateRequest(pkix.Name{CommonName: "test@f110.dev"}, []string{""})
	require.NoError(t, err)

	assert.NotNil(t, privateKey)
	block, _ := pem.Decode(csrByte)
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE REQUEST", block.Type)

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "test@f110.dev", csr.Subject.CommonName)
}

func TestPemEncode(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		f, err := os.CreateTemp("", "")
		require.NoError(t, err)
		defer os.Remove(f.Name())

		privateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		require.NoError(t, err)
		b, err := x509.MarshalECPrivateKey(privateKey)
		require.NoError(t, err)
		err = PemEncode(f.Name(), "EC PRIVATE KEY", b, nil)
		require.NoError(t, err)

		readed, err := os.ReadFile(f.Name())
		require.NoError(t, err)
		block, rest := pem.Decode(readed)
		require.NotNil(t, block)
		require.Len(t, rest, 0)
		require.Equal(t, "EC PRIVATE KEY", block.Type)
	})

	t.Run("Illegal header", func(t *testing.T) {
		f, err := os.CreateTemp("", "")
		require.NoError(t, err)
		defer os.Remove(f.Name())

		err = PemEncode(f.Name(), "ILLEGAL HEADER:", []byte("illegal"), map[string]string{"illegal: ": "value"})
		require.Error(t, err)

		_, err = os.Stat(f.Name())
		require.True(t, os.IsNotExist(err), "if can not encode to pem, should delete a temporary file but not deleted")
	})

	t.Run("Failed create file", func(t *testing.T) {
		err := PemEncode("/unknown/notexist/file/path", "UNKNOWN PATH", []byte("illegal"), nil)
		require.Error(t, err)
	})
}
