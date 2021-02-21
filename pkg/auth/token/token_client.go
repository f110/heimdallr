package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"

	"golang.org/x/xerrors"
)

const (
	ClientRedirectUrl = "http://localhost:6391/callback"
	Directory         = ".heimdallr"
)

type ExchangeResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type Client struct {
	resolver      *net.Resolver
	tokenFilename string
}

func NewClient(resolver *net.Resolver) *Client {
	return &Client{resolver: resolver}
}

func (c *Client) RequestToken(endpoint, overrideOpenURLCommand string, insecure bool) (string, error) {
	verifier := c.newVerifier()

	u, err := url.Parse(endpoint)
	if err != nil {
		return "", xerrors.Errorf(": %v")
	}
	v := &url.Values{}
	v.Set("challenge", c.challenge(verifier))
	v.Set("challenge_method", "S256")
	u.RawQuery = v.Encode()
	u.Path = u.Path + "/authorize"
	if err := OpenBrowser(u.String(), overrideOpenURLCommand); err != nil {
		return "", xerrors.Errorf(": %v", err)
	}

	code, err := c.getCode()
	if err != nil {
		return "", xerrors.Errorf(": %v", err)
	}
	token, err := c.exchangeToken(endpoint, code, verifier, insecure)
	if err != nil {
		return "", xerrors.Errorf(": %w", err)
	}

	return token, nil
}

func (c *Client) exchangeToken(endpoint, code, codeVerifier string, insecure bool) (string, error) {
	v := &url.Values{}
	v.Set("code", code)
	v.Set("code_verifier", codeVerifier)
	req, err := http.NewRequest(http.MethodGet, endpoint+"/exchange?"+v.Encode(), nil)
	if err != nil {
		return "", xerrors.Errorf(": %v", err)
	}
	dialer := &net.Dialer{Resolver: c.resolver}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecure,
			},
		},
	}
	res, err := client.Do(req)
	if err != nil {
		return "", xerrors.Errorf(": %v", err)
	}
	if res.StatusCode != http.StatusOK {
		return "", xerrors.Errorf("localproxy: failure exchange token: Code=%d", res.StatusCode)
	}

	exchange := &ExchangeResponse{}
	if err := json.NewDecoder(res.Body).Decode(exchange); err != nil {
		return "", xerrors.Errorf(": %v", err)
	}

	return exchange.AccessToken, nil
}

func (c *Client) getCode() (string, error) {
	u, err := url.Parse(ClientRedirectUrl)
	if err != nil {
		return "", xerrors.Errorf(": %v", err)
	}

	result := make(chan string)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		result <- req.URL.Query().Get("code")
		io.WriteString(w, `<html><body>Success<br>Close this window</body></html>`)
	})

	s := &http.Server{
		Addr:    u.Host,
		Handler: mux,
	}
	go s.ListenAndServe()

	code := <-result
	s.Shutdown(context.Background())
	return code, nil
}

func (c *Client) newVerifier() string {
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}

func (c *Client) challenge(verifier string) string {
	s := sha256.New()
	s.Write([]byte(verifier))
	return base64.StdEncoding.EncodeToString(s.Sum(nil))
}
