package release

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"go.f110.dev/xerrors"
	"gopkg.in/yaml.v2"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/cmd"
)

type prepareOpt struct {
	Assets            []string
	OutputDir         string
	CACert            string
	CAKey             string
	InjectWebhookCert []string
}

// prepareAssets writes the release assets to OutputDir with the same file names.
// Every processing of the assets that isn't specific to the publishing destination belongs here
// so that e2e can verify the same assets as the release.
func prepareAssets(opt *prepareOpt) error {
	var certs *webhookCerts
	if opt.CACert != "" && opt.CAKey != "" {
		caCert, caKey, err := loadCA(opt.CACert, opt.CAKey)
		if err != nil {
			return err
		}
		certs = &webhookCerts{caCert: caCert, caKey: caKey}
	}

	if err := os.MkdirAll(opt.OutputDir, 0755); err != nil {
		return xerrors.WithStack(err)
	}

	names := make(map[string]struct{})
	for _, v := range opt.Assets {
		name := filepath.Base(v)
		if _, ok := names[name]; ok {
			return xerrors.NewfWithStack("duplicate asset name: %s", name)
		}
		names[name] = struct{}{}

		dst := filepath.Join(opt.OutputDir, name)
		if certs != nil && slices.Contains(opt.InjectWebhookCert, v) {
			if err := injectWebhookCertFile(v, dst, certs); err != nil {
				return err
			}
			continue
		}
		buf, err := os.ReadFile(v)
		if err != nil {
			return xerrors.WithStack(err)
		}
		if err := os.WriteFile(dst, buf, 0644); err != nil {
			return xerrors.WithStack(err)
		}
	}

	return nil
}

func Prepare(rootCmd *cmd.Command) {
	opt := prepareOpt{}

	prepare := &cmd.Command{
		Use:   "prepare",
		Short: "Prepare release assets",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			return prepareAssets(&opt)
		},
	}
	prepare.Flags().StringArray("asset", "Path to an asset file").Var(&opt.Assets)
	prepare.Flags().String("output-dir", "Directory to write the prepared assets").Var(&opt.OutputDir)
	prepare.Flags().String("ca-cert", "Path to CA certificate PEM file for webhook cert injection").Var(&opt.CACert)
	prepare.Flags().String("ca-key", "Path to CA private key PEM file for webhook cert injection").Var(&opt.CAKey)
	prepare.Flags().StringArray("inject-webhook-cert", "Path to an asset file to inject webhook certificates").Var(&opt.InjectWebhookCert)
	rootCmd.AddCommand(prepare)
}

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

// injectWebhookCertFile generates a server certificate for the webhooks referenced in src
// and writes the manifest that the certificate is injected to dst.
// If src doesn't reference any webhook, src is written to dst as is.
func injectWebhookCertFile(src, dst string, certs *webhookCerts) error {
	buf, err := os.ReadFile(src)
	if err != nil {
		return xerrors.WithStack(err)
	}

	dnsNames, err := collectWebhookDNSNames(bytes.NewReader(buf))
	if err != nil {
		return err
	}
	if len(dnsNames) == 0 {
		if err := os.WriteFile(dst, buf, 0644); err != nil {
			return xerrors.WithStack(err)
		}
		return nil
	}

	if err := certs.generateServerCert(dnsNames); err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return xerrors.WithStack(err)
	}
	if err := injectWebhookCert(bytes.NewReader(buf), out, certs); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return xerrors.WithStack(err)
	}
	return nil
}

// collectWebhookDNSNames parses the manifest and collects DNS names from webhook service references.
func collectWebhookDNSNames(in io.Reader) ([]string, error) {
	seen := make(map[string]struct{})
	var dnsNames []string

	d := yaml.NewDecoder(in)
	for {
		v := make(map[any]any)
		err := d.Decode(v)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, xerrors.WithStack(err)
		}

		// ValidatingWebhookConfiguration / MutatingWebhookConfiguration
		if webhooks, ok := v["webhooks"].([]any); ok {
			for _, wh := range webhooks {
				whMap, ok := wh.(map[any]any)
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
		if spec, ok := v["spec"].(map[any]any); ok {
			if conv, ok := spec["conversion"].(map[any]any); ok {
				if wh, ok := conv["webhook"].(map[any]any); ok {
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
func serviceDNSName(v map[any]any) string {
	cc, ok := v["clientConfig"].(map[any]any)
	if !ok {
		return ""
	}
	svc, ok := cc["service"].(map[any]any)
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
		v := make(map[any]any)
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

func getInjectAnnotation(v map[any]any) string {
	metadata, ok := v["metadata"].(map[any]any)
	if !ok {
		return ""
	}
	annotations, ok := metadata["annotations"].(map[any]any)
	if !ok {
		return ""
	}
	val, ok := annotations[injectAnnotationKey].(string)
	if !ok {
		return ""
	}
	return val
}

func removeInjectAnnotation(v map[any]any) {
	metadata, ok := v["metadata"].(map[any]any)
	if !ok {
		return
	}
	annotations, ok := metadata["annotations"].(map[any]any)
	if !ok {
		return
	}
	delete(annotations, injectAnnotationKey)
	if len(annotations) == 0 {
		delete(metadata, "annotations")
	}
}

func processCertInjection(v map[any]any, certs *webhookCerts) {
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

func injectServerCertSecret(v map[any]any, certs *webhookCerts) {
	sd, ok := v["stringData"].(map[any]any)
	if !ok {
		return
	}
	sd["webhook.crt"] = string(certs.serverCertPEM)
	sd["webhook.key"] = string(certs.serverKeyPEM)
}

func injectCABundleField(v map[any]any, certs *webhookCerts) {
	caBundle := base64.StdEncoding.EncodeToString(certs.serverCertPEM)

	webhooks, ok := v["webhooks"].([]any)
	if !ok {
		return
	}
	for _, wh := range webhooks {
		whMap, ok := wh.(map[any]any)
		if !ok {
			continue
		}
		cc, ok := whMap["clientConfig"].(map[any]any)
		if !ok {
			continue
		}
		cc["caBundle"] = caBundle
	}
}

func injectCRDConversionCABundle(v map[any]any, certs *webhookCerts) {
	spec, ok := v["spec"].(map[any]any)
	if !ok {
		return
	}
	conv, ok := spec["conversion"].(map[any]any)
	if !ok {
		return
	}
	wh, ok := conv["webhook"].(map[any]any)
	if !ok {
		return
	}
	cc, ok := wh["clientConfig"].(map[any]any)
	if !ok {
		return
	}
	if _, ok := cc["caBundle"]; !ok {
		return
	}
	cc["caBundle"] = base64.StdEncoding.EncodeToString(certs.serverCertPEM)
}
