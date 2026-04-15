package release

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"go.f110.dev/xerrors"
	"gopkg.in/yaml.v2"

	"go.f110.dev/heimdallr/pkg/cert"
)

const (
	injectAnnotationKey = "internal.heimdallr.f110.dev/inject"
	injectServerCert    = "webhook-server-cert"
	injectCABundle      = "webhook-ca-bundle"
)

type webhookCerts struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey

	serverCertPEM []byte
	serverKeyPEM  []byte
}

func loadCA(caCertFile, caKeyFile string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	caCertPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, nil, xerrors.New("failed to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}

	caKeyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}
	block, _ = pem.Decode(caKeyPEM)
	if block == nil {
		return nil, nil, xerrors.New("failed to decode CA private key PEM")
	}
	caKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}

	return caCert, caKey, nil
}

func (c *webhookCerts) generateServerCert(dnsNames []string) error {
	serverCert, serverKey, err := cert.GenerateServerCertificate(c.caCert, c.caKey, dnsNames)
	if err != nil {
		return err
	}

	certBuf := new(bytes.Buffer)
	if err := pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw}); err != nil {
		return xerrors.WithStack(err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(serverKey.(*ecdsa.PrivateKey))
	if err != nil {
		return xerrors.WithStack(err)
	}
	keyBuf := new(bytes.Buffer)
	if err := pem.Encode(keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return xerrors.WithStack(err)
	}

	c.serverCertPEM = certBuf.Bytes()
	c.serverKeyPEM = keyBuf.Bytes()
	return nil
}

// maybeInjectWebhookCert checks if the file contains webhook inject annotations.
// If it does, it generates a server certificate, injects it, and returns the path
// to a temporary file with the injected content. Returns "" if no injection was needed.
func maybeInjectWebhookCert(path string, certs *webhookCerts) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", xerrors.WithStack(err)
	}
	defer f.Close()

	// First pass: collect DNS names from webhook service references
	dnsNames, err := collectWebhookDNSNames(f)
	if err != nil {
		return "", err
	}
	if len(dnsNames) == 0 {
		return "", nil
	}

	// Generate certificate with collected DNS names
	if err := certs.generateServerCert(dnsNames); err != nil {
		return "", err
	}

	// Second pass: inject certificates
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", xerrors.WithStack(err)
	}

	tmp, err := os.CreateTemp("", "webhook-cert-injected-*.yaml")
	if err != nil {
		return "", xerrors.WithStack(err)
	}
	defer tmp.Close()

	if err := injectWebhookCert(f, tmp, certs); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}

	return tmp.Name(), nil
}

// collectWebhookDNSNames parses the manifest and collects DNS names from webhook service references.
func collectWebhookDNSNames(in io.Reader) ([]string, error) {
	seen := make(map[string]struct{})
	var dnsNames []string

	d := yaml.NewDecoder(in)
	for {
		v := make(map[interface{}]interface{})
		err := d.Decode(v)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, xerrors.WithStack(err)
		}

		// ValidatingWebhookConfiguration / MutatingWebhookConfiguration
		if webhooks, ok := v["webhooks"].([]interface{}); ok {
			for _, wh := range webhooks {
				whMap, ok := wh.(map[interface{}]interface{})
				if !ok {
					continue
				}
				if name := serviceDNSName(whMap); name != "" {
					if _, ok := seen[name]; !ok {
						seen[name] = struct{}{}
						dnsNames = append(dnsNames, name)
					}
				}
			}
		}

		// CRD conversion webhook
		if spec, ok := v["spec"].(map[interface{}]interface{}); ok {
			if conv, ok := spec["conversion"].(map[interface{}]interface{}); ok {
				if wh, ok := conv["webhook"].(map[interface{}]interface{}); ok {
					if name := serviceDNSName(wh); name != "" {
						if _, ok := seen[name]; !ok {
							seen[name] = struct{}{}
							dnsNames = append(dnsNames, name)
						}
					}
				}
			}
		}
	}

	return dnsNames, nil
}

// serviceDNSName extracts "<name>.<namespace>.svc" from a map that has clientConfig.service.
func serviceDNSName(v map[interface{}]interface{}) string {
	cc, ok := v["clientConfig"].(map[interface{}]interface{})
	if !ok {
		return ""
	}
	svc, ok := cc["service"].(map[interface{}]interface{})
	if !ok {
		return ""
	}
	name, _ := svc["name"].(string)
	namespace, _ := svc["namespace"].(string)
	if name == "" || namespace == "" {
		return ""
	}
	return fmt.Sprintf("%s.%s.svc", name, namespace)
}

func injectWebhookCert(in io.Reader, out io.Writer, certs *webhookCerts) error {
	d := yaml.NewDecoder(in)
	e := yaml.NewEncoder(out)
	for {
		v := make(map[interface{}]interface{})
		err := d.Decode(v)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return xerrors.WithStack(err)
		}

		processCertInjection(v, certs)

		if err := e.Encode(v); err != nil {
			return xerrors.WithStack(err)
		}
	}
	if err := e.Close(); err != nil {
		return xerrors.WithStack(err)
	}
	return nil
}

func getInjectAnnotation(v map[interface{}]interface{}) string {
	metadata, ok := v["metadata"].(map[interface{}]interface{})
	if !ok {
		return ""
	}
	annotations, ok := metadata["annotations"].(map[interface{}]interface{})
	if !ok {
		return ""
	}
	val, ok := annotations[injectAnnotationKey].(string)
	if !ok {
		return ""
	}
	return val
}

func removeInjectAnnotation(v map[interface{}]interface{}) {
	metadata, ok := v["metadata"].(map[interface{}]interface{})
	if !ok {
		return
	}
	annotations, ok := metadata["annotations"].(map[interface{}]interface{})
	if !ok {
		return
	}
	delete(annotations, injectAnnotationKey)
	if len(annotations) == 0 {
		delete(metadata, "annotations")
	}
}

func processCertInjection(v map[interface{}]interface{}, certs *webhookCerts) {
	inject := getInjectAnnotation(v)
	switch inject {
	case injectServerCert:
		injectServerCertSecret(v, certs)
		removeInjectAnnotation(v)
	case injectCABundle:
		injectCABundleField(v, certs)
		removeInjectAnnotation(v)
	default:
		// For CRDs (whose annotations are stripped by manifest-cleaner),
		// detect conversion webhooks automatically.
		injectCRDConversionCABundle(v, certs)
	}
}

func injectServerCertSecret(v map[interface{}]interface{}, certs *webhookCerts) {
	sd, ok := v["stringData"].(map[interface{}]interface{})
	if !ok {
		return
	}
	sd["webhook.crt"] = string(certs.serverCertPEM)
	sd["webhook.key"] = string(certs.serverKeyPEM)
}

func injectCABundleField(v map[interface{}]interface{}, certs *webhookCerts) {
	caBundle := base64.StdEncoding.EncodeToString(certs.serverCertPEM)

	webhooks, ok := v["webhooks"].([]interface{})
	if !ok {
		return
	}
	for _, wh := range webhooks {
		whMap, ok := wh.(map[interface{}]interface{})
		if !ok {
			continue
		}
		cc, ok := whMap["clientConfig"].(map[interface{}]interface{})
		if !ok {
			continue
		}
		cc["caBundle"] = caBundle
	}
}

func injectCRDConversionCABundle(v map[interface{}]interface{}, certs *webhookCerts) {
	spec, ok := v["spec"].(map[interface{}]interface{})
	if !ok {
		return
	}
	conv, ok := spec["conversion"].(map[interface{}]interface{})
	if !ok {
		return
	}
	wh, ok := conv["webhook"].(map[interface{}]interface{})
	if !ok {
		return
	}
	cc, ok := wh["clientConfig"].(map[interface{}]interface{})
	if !ok {
		return
	}
	if _, ok := cc["caBundle"]; !ok {
		return
	}
	cc["caBundle"] = base64.StdEncoding.EncodeToString(certs.serverCertPEM)
}
