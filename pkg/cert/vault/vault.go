package vault

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"

	"golang.org/x/xerrors"
)

var (
	ErrOperationNotPermitted = Error{Message: "operation is not permitted"}
)

type Error struct {
	Message        string
	StatusCode     int
	VerboseMessage string
}

type ErrMessage struct {
	Errors []string
}

func (e Error) Error() string {
	return e.Message
}

func (e Error) Verbose() string {
	if e.VerboseMessage == "" {
		return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("%d: %s", e.StatusCode, e.VerboseMessage)
}

type ClientOpt func(*clientOpt)

type clientOpt struct {
	HttpClient *http.Client
}

func HttpClient(c *http.Client) ClientOpt {
	return func(opt *clientOpt) {
		opt.HttpClient = c
	}
}

type Client struct {
	addr       *url.URL
	httpClient *http.Client
	token      string
	mountPath  string
	role       string

	certPool *x509.CertPool
	caCert   *x509.Certificate
}

// NewClient makes a client for Vault PKI with a static token
func NewClient(addr, token, mountPath, role string, opts ...ClientOpt) (*Client, error) {
	opt := &clientOpt{}
	for _, v := range opts {
		v(opt)
	}

	u, err := url.Parse(addr)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	httpClient := opt.HttpClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	return &Client{addr: u, token: token, mountPath: mountPath, role: role, httpClient: httpClient}, nil
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
	req, err := c.newRequest(ctx, http.MethodGet, path.Join("v1", c.mountPath, "ca"), nil)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		return nil, xerrors.Errorf(": %w", ErrOperationNotPermitted)
	}
	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	cert, err := x509.ParseCertificate(buf)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	return cert, nil
}

func (c *Client) GenerateCertificate(ctx context.Context, commonName string, altNames []string) (*x509.Certificate, crypto.PrivateKey, error) {
	req, err := c.newRequest(
		ctx,
		http.MethodPost,
		path.Join("v1", c.mountPath, "issue", c.role),
		map[string]any{
			"common_name":        commonName,
			"alt_names":          strings.Join(altNames, ","),
			"format":             "der",
			"private_key_format": "pkcs8",
		},
	)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %w", err)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		return nil, nil, xerrors.Errorf(": %w", ErrOperationNotPermitted)
	}

	b, _ := httputil.DumpResponse(res, true)
	log.Print(string(b))

	resObj := &PKIResponse{}
	if err := json.NewDecoder(res.Body).Decode(resObj); err != nil {
		return nil, nil, xerrors.Errorf(": %w", err)
	}
	certBytes, err := base64.StdEncoding.DecodeString(resObj.Data.Certificate)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %w", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %w", err)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(resObj.Data.PrivateKey)
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
	req, err := c.newRequest(
		ctx,
		http.MethodPost,
		path.Join("v1", c.mountPath, "sign", c.role),
		map[string]any{
			"csr":         buf.String(),
			"common_name": csr.Subject.CommonName,
			"format":      "der",
		},
	)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		return nil, xerrors.Errorf(": %w", ErrOperationNotPermitted)
	}

	resObj := &PKIResponse{}
	if err := json.NewDecoder(res.Body).Decode(resObj); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	certBytes, err := base64.StdEncoding.DecodeString(resObj.Data.Certificate)
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
	req, err := c.newRequest(
		ctx,
		http.MethodPost,
		path.Join("v1", c.mountPath, "revoke"),
		map[string]any{
			"serial_number": strings.ReplaceAll(fmt.Sprintf("% x", cert.SerialNumber.Bytes()), " ", ":"),
		},
	)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		return xerrors.Errorf(": %w", ErrOperationNotPermitted)
	}

	return nil
}

func (c *Client) EnablePKI(ctx context.Context) error {
	req, err := c.newRequest(ctx, http.MethodPost, path.Join("v1/sys/mounts", c.mountPath), map[string]any{"type": "pki"})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	res, err := c.httpClient.Do(req)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		return xerrors.Errorf(": %w", ErrOperationNotPermitted)
	}

	req, err = c.newRequest(ctx, http.MethodPost, path.Join("v1/sys/mounts", c.mountPath, "tune"), map[string]any{"max_lease_ttl": "8760h"})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	res, err = c.httpClient.Do(req)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		return xerrors.Errorf(": %w", ErrOperationNotPermitted)
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

	req, err := c.newRequest(
		ctx,
		http.MethodPost,
		path.Join("v1", c.mountPath, "config/ca"),
		map[string]any{
			"pem_bundle": pemBundle.String(),
		},
	)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	res, err := c.httpClient.Do(req)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		return xerrors.Errorf(": %w", ErrOperationNotPermitted)
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
	body := new(bytes.Buffer)
	if err := json.NewEncoder(body).Encode(role); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	req, err := c.newRequestWithRawBody(
		ctx,
		http.MethodPost,
		path.Join("v1", c.mountPath, "roles", name),
		body,
	)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		return xerrors.Errorf(": %w", ErrOperationNotPermitted)
	}
	return nil
}

func (c *Client) GenerateRoot(ctx context.Context, commonName string) error {
	req, err := c.newRequest(
		ctx,
		http.MethodPost,
		path.Join("v1", c.mountPath, "root/generate/internal"),
		map[string]any{
			"common_name": commonName,
			"ttl":         "26280h", // 3 years
		},
	)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	res, err := c.httpClient.Do(req)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, body map[string]any) (*http.Request, error) {
	var bodyBytes io.Reader
	if body != nil {
		b := new(bytes.Buffer)
		if err := json.NewEncoder(b).Encode(body); err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		bodyBytes = b
	}
	return c.newRequestWithRawBody(ctx, method, path, bodyBytes)
}

func (c *Client) newRequestWithRawBody(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	u := &url.URL{}
	*u = *c.addr
	u.Path = path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)
	return req, nil
}

// PKIResponse represents the response of PKI engine.
type PKIResponse struct {
	LeaseId       string `json:"lease_id"`
	Renewable     bool   `json:"renewable"`
	LeaseDuration int    `json:"lease_duration"`
	Data          struct {
		Certificate    string   `json:"certificate"`
		IssuingCA      string   `json:"issuing_ca"`
		CAChain        []string `json:"ca_chain"`
		PrivateKey     string   `json:"private_key"`
		PrivateKeyType string   `json:"private_key_type"`
		SerialNumber   string   `json:"serial_number"`
	} `json:"data"`
	Warnings []string `json:"warnings"`
	Auth     any      `json:"auth"`
}
