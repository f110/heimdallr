package release

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"go.f110.dev/heimdallr/pkg/cert"
)

func setupTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caCert, caKey, err := cert.CreateCertificateAuthority("test CA", "", "", "", "ecdsa")
	require.NoError(t, err)
	return caCert, caKey.(*ecdsa.PrivateKey)
}

func writeCAFiles(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (string, string) {
	t.Helper()
	dir := t.TempDir()

	certBuf := new(bytes.Buffer)
	require.NoError(t, pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))
	certFile := dir + "/ca.crt"
	require.NoError(t, os.WriteFile(certFile, certBuf.Bytes(), 0644))

	keyBytes, err := x509.MarshalECPrivateKey(caKey)
	require.NoError(t, err)
	keyBuf := new(bytes.Buffer)
	require.NoError(t, pem.Encode(keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))
	keyFile := dir + "/ca.key"
	require.NoError(t, os.WriteFile(keyFile, keyBuf.Bytes(), 0644))

	return certFile, keyFile
}

const testManifest = `apiVersion: v1
kind: Secret
metadata:
  name: webhook-cert
  annotations:
    internal.heimdallr.f110.dev/inject: webhook-server-cert
stringData:
  webhook.crt: old-cert
  webhook.key: old-key
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: test-webhook
  annotations:
    internal.heimdallr.f110.dev/inject: webhook-ca-bundle
webhooks:
  - admissionReviewVersions: ["v1"]
    clientConfig:
      service:
        name: webhook
        namespace: mynamespace
        path: /validate
      caBundle: b2xkLWNhLWJ1bmRsZQ==
    name: test.example.com
    sideEffects: None
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: tests.example.com
spec:
  conversion:
    strategy: Webhook
    webhook:
      conversionReviewVersions: ["v1"]
      clientConfig:
        service:
          namespace: mynamespace
          name: webhook
          path: /conversion
        caBundle: b2xkLWNhLWJ1bmRsZQ==
`

func TestCollectWebhookDNSNames(t *testing.T) {
	cases := []struct {
		Manifest string
		DNSNames []string
	}{
		{
			Manifest: `apiVersion: v1
kind: Secret
metadata:
  name: webhook-cert
  annotations:
    internal.heimdallr.f110.dev/inject: webhook-server-cert
stringData:
  webhook.crt: old-cert
  webhook.key: old-key
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: test-webhook
  annotations:
    internal.heimdallr.f110.dev/inject: webhook-ca-bundle
webhooks:
  - admissionReviewVersions: ["v1"]
    clientConfig:
      service:
        name: webhook
        namespace: mynamespace
        path: /validate
      caBundle: b2xkLWNhLWJ1bmRsZQ==
    name: test.example.com
    sideEffects: None
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: tests.example.com
spec:
  conversion:
    strategy: Webhook
    webhook:
      conversionReviewVersions: ["v1"]
      clientConfig:
        service:
          namespace: mynamespace
          name: webhook
          path: /conversion
        caBundle: b2xkLWNhLWJ1bmRsZQ==
`,
			DNSNames: []string{"webhook.mynamespace.svc"},
		},
		{
			Manifest: `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: wh1
webhooks:
  - clientConfig:
      service:
        name: svc-a
        namespace: ns1
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: wh2
webhooks:
  - clientConfig:
      service:
        name: svc-b
        namespace: ns2
  - clientConfig:
      service:
        name: svc-a
        namespace: ns1
`,
			DNSNames: []string{"svc-a.ns1.svc", "svc-b.ns2.svc"},
		},
		{
			Manifest: `apiVersion: v1
kind: ConfigMap
metadata:
  name: test`,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			dnsNames, err := collectWebhookDNSNames(strings.NewReader(tc.Manifest))
			require.NoError(t, err)
			if tc.DNSNames == nil {
				assert.Empty(t, dnsNames)
			} else {
				assert.Equal(t, tc.DNSNames, dnsNames)
			}
		})
	}
}

func TestInjectWebhookCert(t *testing.T) {
	caCert, caKey := setupTestCA(t)

	certs := &webhookCerts{caCert: caCert, caKey: caKey}
	require.NoError(t, certs.generateServerCert([]string{"webhook.mynamespace.svc"}))

	var out bytes.Buffer
	err := injectWebhookCert(strings.NewReader(testManifest), &out, certs)
	require.NoError(t, err)

	// Parse all documents from the output
	docs := parseAllDocs(t, out.Bytes())
	require.Len(t, docs, 3)

	// Verify Secret: cert and key are replaced, annotation is removed
	secret := docs[0]
	sd := secret["stringData"].(map[interface{}]interface{})
	certPEM := sd["webhook.crt"].(string)
	keyPEM := sd["webhook.key"].(string)
	assert.NotEqual(t, "old-cert", certPEM)
	assert.NotEqual(t, "old-key", keyPEM)
	assert.Contains(t, certPEM, "BEGIN CERTIFICATE")
	assert.Contains(t, keyPEM, "BEGIN EC PRIVATE KEY")
	assertNoInjectAnnotation(t, secret)

	// Verify the injected cert is valid and signed by the CA
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	serverCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, []string{"webhook.mynamespace.svc"}, serverCert.DNSNames)
	err = serverCert.CheckSignatureFrom(caCert)
	assert.NoError(t, err)

	// Verify the injected key matches the cert
	block, _ = pem.Decode([]byte(keyPEM))
	require.NotNil(t, block)
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	require.NoError(t, err)
	assert.True(t, serverCert.PublicKey.(*ecdsa.PublicKey).Equal(&privKey.PublicKey))

	// Verify ValidatingWebhookConfiguration: caBundle is replaced, annotation is removed
	vwc := docs[1]
	webhooks := vwc["webhooks"].([]interface{})
	cc := webhooks[0].(map[interface{}]interface{})["clientConfig"].(map[interface{}]interface{})
	caBundle := cc["caBundle"].(string)
	assert.NotEqual(t, "b2xkLWNhLWJ1bmRsZQ==", caBundle)
	decoded, err := base64.StdEncoding.DecodeString(caBundle)
	require.NoError(t, err)
	assert.Equal(t, string(certs.serverCertPEM), string(decoded))
	assertNoInjectAnnotation(t, vwc)

	// Verify CRD conversion webhook: caBundle is replaced (detected automatically)
	crd := docs[2]
	crdCC := crd["spec"].(map[interface{}]interface{})["conversion"].(map[interface{}]interface{})["webhook"].(map[interface{}]interface{})["clientConfig"].(map[interface{}]interface{})
	crdCABundle := crdCC["caBundle"].(string)
	assert.NotEqual(t, "b2xkLWNhLWJ1bmRsZQ==", crdCABundle)
	decoded, err = base64.StdEncoding.DecodeString(crdCABundle)
	require.NoError(t, err)
	assert.Equal(t, string(certs.serverCertPEM), string(decoded))
}

func TestMaybeInjectWebhookCert(t *testing.T) {
	caCert, caKey := setupTestCA(t)

	// Write test manifest to a temp file
	dir := t.TempDir()
	manifestFile := dir + "/all-in-one.yaml"
	require.NoError(t, os.WriteFile(manifestFile, []byte(testManifest), 0644))

	certs := &webhookCerts{caCert: caCert, caKey: caKey}
	injected, err := maybeInjectWebhookCert(manifestFile, certs)
	require.NoError(t, err)
	require.NotEmpty(t, injected)
	defer os.Remove(injected)

	// Read the injected file and verify
	result, err := os.ReadFile(injected)
	require.NoError(t, err)

	docs := parseAllDocs(t, result)
	require.Len(t, docs, 3)

	// Secret should have new cert
	sd := docs[0]["stringData"].(map[interface{}]interface{})
	assert.Contains(t, sd["webhook.crt"].(string), "BEGIN CERTIFICATE")
	assert.NotEqual(t, "old-cert", sd["webhook.crt"])

	// Server cert should have the correct DNS name
	assert.NotNil(t, certs.serverCertPEM)
	block, _ := pem.Decode(certs.serverCertPEM)
	require.NotNil(t, block)
	serverCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, []string{"webhook.mynamespace.svc"}, serverCert.DNSNames)
}

func TestMaybeInjectWebhookCert_NoWebhooks(t *testing.T) {
	caCert, caKey := setupTestCA(t)

	manifest := `apiVersion: v1
kind: ConfigMap
metadata:
  name: test
data:
  key: value
`
	dir := t.TempDir()
	manifestFile := dir + "/no-webhook.yaml"
	require.NoError(t, os.WriteFile(manifestFile, []byte(manifest), 0644))

	certs := &webhookCerts{caCert: caCert, caKey: caKey}
	injected, err := maybeInjectWebhookCert(manifestFile, certs)
	require.NoError(t, err)
	assert.Empty(t, injected, "should return empty string when no webhooks found")
}

func TestLoadCA(t *testing.T) {
	caCert, caKey := setupTestCA(t)
	certFile, keyFile := writeCAFiles(t, caCert, caKey)

	loadedCert, loadedKey, err := loadCA(certFile, keyFile)
	require.NoError(t, err)
	assert.Equal(t, caCert.Raw, loadedCert.Raw)
	assert.True(t, caKey.Equal(loadedKey))
}

func parseAllDocs(t *testing.T, data []byte) []map[interface{}]interface{} {
	t.Helper()
	var docs []map[interface{}]interface{}
	d := yaml.NewDecoder(bytes.NewReader(data))
	for {
		v := make(map[interface{}]interface{})
		err := d.Decode(v)
		if err != nil {
			break
		}
		docs = append(docs, v)
	}
	return docs
}

func assertNoInjectAnnotation(t *testing.T, v map[interface{}]interface{}) {
	t.Helper()
	metadata, ok := v["metadata"].(map[interface{}]interface{})
	if !ok {
		return
	}
	annotations, ok := metadata["annotations"].(map[interface{}]interface{})
	if !ok {
		return
	}
	_, exists := annotations[injectAnnotationKey]
	assert.False(t, exists, "inject annotation should be removed")
}
