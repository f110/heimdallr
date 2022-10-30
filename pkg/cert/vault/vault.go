package vault

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"golang.org/x/xerrors"
)

type Client struct {
	client *api.Client
	role   string

	certPool *x509.CertPool
	caCert   *x509.Certificate
}

func NewClient(addr, token, role string) (*Client, error) {
	vault, err := api.NewClient(&api.Config{Address: addr})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	vault.SetToken(token)

	return &Client{client: vault, role: role}, nil
}

func (c *Client) GetCertPool(ctx context.Context) (*x509.CertPool, error) {
	if c.certPool != nil {
		return c.certPool, nil
	}

	caCert, err := c.GetCACertificate(ctx)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	certPool.AddCert(caCert)

	c.certPool = certPool
	return certPool, nil
}

func (c *Client) GetCACertificate(ctx context.Context) (*x509.Certificate, error) {
	if c.caCert != nil {
		return c.caCert, nil
	}

	caCert, err := c.getCACert(ctx)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	c.caCert = caCert
	return caCert, nil
}

func (c *Client) getCACert(ctx context.Context) (*x509.Certificate, error) {
	req := c.client.NewRequest(http.MethodGet, "/v1/pki/ca")
	rCtx, cancel := context.WithTimeout(ctx, time.Second)
	res, err := c.client.RawRequestWithContext(rCtx, req)
	cancel()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, xerrors.Errorf("unexpected response: %s", res.Status)
	}
	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if len(buf) == 0 {
		return nil, xerrors.Errorf("response is empty")
	}
	caCert, err := x509.ParseCertificate(buf)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return caCert, nil
}

func (c *Client) GenerateCertificate(ctx context.Context, commonName string, altNames []string) (*x509.Certificate, crypto.PrivateKey, error) {
	req := c.client.NewRequest(http.MethodPost, fmt.Sprintf("/v1/pki/issue/%s", c.role))
	err := req.SetJSONBody(map[string]interface{}{
		"common_name":        commonName,
		"alt_names":          strings.Join(altNames, ","),
		"format":             "der",
		"private_key_format": "pkcs8",
	})
	rCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	res, err := c.client.RawRequestWithContext(rCtx, req)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, nil, xerrors.Errorf("unexpected response: %s", res.Status)
	}
	secret, err := api.ParseSecret(res.Body)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %w", err)
	}
	certBytes, err := base64.StdEncoding.DecodeString(secret.Data["certificate"].(string))
	if err != nil {
		return nil, nil, xerrors.Errorf(": %w", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %w", err)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(secret.Data["private_key"].(string))
	if err != nil {
		return nil, nil, xerrors.Errorf(": %w", err)
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %w", err)
	}

	return cert, privateKey, nil
}

func (c *Client) Sign(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Bytes: csr.Raw, Type: "CERTIFICATE REQUEST"}); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	req := c.client.NewRequest(http.MethodPost, fmt.Sprintf("/v1/pki/sign/%s", c.role))
	err := req.SetJSONBody(map[string]interface{}{
		"csr":         buf.String(),
		"common_name": csr.Subject.CommonName,
		"format":      "der",
	})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	rCtx, cancel := context.WithTimeout(ctx, time.Second)
	res, err := c.client.RawRequestWithContext(rCtx, req)
	cancel()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	defer res.Body.Close()
	secret, err := api.ParseSecret(res.Body)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	certBytes, err := base64.StdEncoding.DecodeString(secret.Data["certificate"].(string))
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return cert, nil
}

func (c *Client) Revoke(ctx context.Context, cert *x509.Certificate) error {
	req := c.client.NewRequest(http.MethodPost, "/v1/pki/revoke")
	err := req.SetJSONBody(map[string]interface{}{
		"serial_number": strings.ReplaceAll(fmt.Sprintf("% x", cert.SerialNumber.Bytes()), " ", ":"),
	})
	rCtx, cancel := context.WithTimeout(ctx, time.Second)
	res, err := c.client.RawRequestWithContext(rCtx, req)
	cancel()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return xerrors.Errorf("unexpected response: %s", res.Status)
	}

	return nil
}

func (c *Client) EnablePKI(_ context.Context) error {
	err := c.client.Sys().Mount("pki/", &api.MountInput{
		Type: "pki",
	})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	err = c.client.Sys().TuneMount("pki/", api.MountConfigInput{
		MaxLeaseTTL: "8760h",
	})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (c *Client) SetCA(ctx context.Context, cert *x509.Certificate, privateKey crypto.PrivateKey) error {
	pemBundle := new(bytes.Buffer)
	if err := pem.Encode(pemBundle, &pem.Block{Bytes: cert.Raw, Type: "CERTIFICATE"}); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	switch v := privateKey.(type) {
	case *rsa.PrivateKey:
		b, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		if err := pem.Encode(pemBundle, &pem.Block{Bytes: b, Type: "RSA PRIVATE KEY"}); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(v)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		if err := pem.Encode(pemBundle, &pem.Block{Bytes: b, Type: "EC PRIVATE KEY"}); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	req := c.client.NewRequest(http.MethodPost, "/v1/pki/config/ca")
	if err := req.SetJSONBody(map[string]interface{}{"pem_bundle": pemBundle.String()}); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	rCtx, cancel := context.WithTimeout(ctx, time.Second)
	res, err := c.client.RawRequestWithContext(rCtx, req)
	cancel()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK, http.StatusNoContent:
	default:
		return xerrors.Errorf("can not set ca: %s", res.Status)
	}
	io.Copy(io.Discard, res.Body)

	return nil
}

type Role struct {
	AllowLocalhost                bool     `json:"allow_localhost,omitempty"`
	AllowedDomains                []string `json:"allowed_domains,omitempty"`
	AllowDomainsTemplate          bool     `json:"allow_domains_template,omitempty"`
	AllowBareDomains              bool     `json:"allow_bare_domains,omitempty"`
	AllowSubDomains               bool     `json:"allow_sub_domains,omitempty"`
	AllowGlobDomains              bool     `json:"allow_glob_domains,omitempty"`
	AllowAnyName                  bool     `json:"allow_any_name,omitempty"`
	EnforceHostnames              bool     `json:"enforce_hostnames"`
	AllowIPSans                   bool     `json:"allow_ip_sans,omitempty"`
	AllowedURISANS                string   `json:"allowed_uri_sans,omitempty"`
	AllowedOtherSANS              string   `json:"allowed_other_sans,omitempty"`
	ServerFlag                    bool     `json:"server_flag,omitempty"`
	ClientFlag                    bool     `json:"client_flag,omitempty"`
	CodeSigningFlag               bool     `json:"code_signing_flag,omitempty"`
	EmailProtectionFlag           bool     `json:"email_protection_flag,omitempty"`
	KeyType                       string   `json:"key_type,omitempty"`
	KeyBits                       int      `json:"key_bits,omitempty"`
	KeyUsage                      []string `json:"key_usage,omitempty"`
	ExtKeyUsage                   []string `json:"ext_key_usage,omitempty"`
	ExtKeyUsageOIDs               string   `json:"ext_key_usage_oids,omitempty"`
	UseCSRCommonName              bool     `json:"use_csr_common_name,omitempty"`
	UseCSRSans                    bool     `json:"use_csr_sans,omitempty"`
	OU                            string   `json:"ou,omitempty"`
	Organization                  string   `json:"organization,omitempty"`
	Country                       string   `json:"country,omitempty"`
	Locality                      string   `json:"locality,omitempty"`
	Province                      string   `json:"province,omitempty"`
	StreetAddress                 string   `json:"street_address,omitempty"`
	PostalCode                    string   `json:"postal_code,omitempty"`
	SerialNumber                  string   `json:"serial_number,omitempty"`
	GenerateLease                 bool     `json:"generate_lease,omitempty"`
	NoStore                       bool     `json:"no_store,omitempty"`
	RequireCN                     bool     `json:"require_cn,omitempty"`
	PolicyIdentifiers             []string `json:"policy_identifiers,omitempty"`
	BasisConstraintsValidForNonCA bool     `json:"basis_constraints_valid_for_non_ca,omitempty"`
	NotBeforeDuration             string   `json:"not_before_duration,omitempty"`
}

func (c *Client) SetRole(ctx context.Context, name string, role *Role) error {
	req := c.client.NewRequest(http.MethodPost, fmt.Sprintf("/v1/pki/roles/%s", name))
	if err := req.SetJSONBody(role); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	rCtx, cancel := context.WithTimeout(ctx, time.Second)
	res, err := c.client.RawRequestWithContext(rCtx, req)
	cancel()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK, http.StatusNoContent:
	default:
		return xerrors.Errorf("unexpected response: %s", res.Status)
	}

	return nil
}

func (c *Client) GenerateRoot(ctx context.Context, commonName string) error {
	req := c.client.NewRequest(http.MethodPost, "/v1/pki/root/generate/internal")
	if err := req.SetJSONBody(map[string]interface{}{
		"common_name": commonName,
		"ttl":         "26280h", // 3 years
	}); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	rCtx, cancel := context.WithTimeout(ctx, time.Second)
	res, err := c.client.RawRequestWithContext(rCtx, req)
	cancel()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return xerrors.Errorf("unexpected response: %s", res.Status)
	}

	return nil
}
