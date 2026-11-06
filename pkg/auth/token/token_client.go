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
	"time"

	"go.f110.dev/xerrors"
)

const (
	ClientRedirectUrl = "http://127.0.0.1:6391/callback"
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

// RequestToken opens the browser to authorize and waits for the callback until ctx is done.
func (c *Client) RequestToken(ctx context.Context, endpoint, overrideOpenURLCommand string, insecure bool) (string, time.Time, error) {
	verifier := c.newVerifier()

	u, err := url.Parse(endpoint)
	if err != nil {
		return "", time.Time{}, xerrors.WithStack(err)
	}
	redirectURL, err := url.Parse(ClientRedirectUrl)
	if err != nil {
		return "", time.Time{}, xerrors.WithStack(err)
	}
	l, err := net.Listen("tcp", redirectURL.Host)
	if err != nil {
		return "", time.Time{}, xerrors.WithStack(err)
	}
	codeCh := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		select {
		case codeCh <- req.URL.Query().Get("code"):
		default:
		}
		io.WriteString(w, `<html><body>Success<br>Close this window</body></html>`)
	})
	s := &http.Server{Handler: mux}
	go s.Serve(l)
	defer func() {
		s.Shutdown(context.Background())
		l.Close()
	}()

	v := &url.Values{}
	v.Set("challenge", c.challenge(verifier))
	v.Set("challenge_method", "S256")
	u.RawQuery = v.Encode()
	u.Path = u.Path + "/authorize"
	if err := OpenBrowser(u.String(), overrideOpenURLCommand); err != nil {
		return "", time.Time{}, err
	}

	var code string
	select {
	case code = <-codeCh:
	case <-ctx.Done():
		return "", time.Time{}, xerrors.WithStack(ctx.Err())
	}
	now := time.Now()
	res, err := c.exchangeToken(endpoint, code, verifier, insecure)
	if err != nil {
		return "", time.Time{}, err
	}

	return res.AccessToken, now.Add(time.Duration(res.ExpiresIn) * time.Second), nil
}

func (c *Client) exchangeToken(endpoint, code, codeVerifier string, insecure bool) (*ExchangeResponse, error) {
	v := &url.Values{}
	v.Set("code", code)
	v.Set("code_verifier", codeVerifier)
	req, err := http.NewRequest(http.MethodGet, endpoint+"/exchange?"+v.Encode(), nil)
	if err != nil {
		return nil, xerrors.WithStack(err)
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
		return nil, xerrors.WithStack(err)
	}
	if res.StatusCode != http.StatusOK {
		return nil, xerrors.NewfWithStack("localproxy: failure exchange token: Code=%d", res.StatusCode)
	}

	exchange := &ExchangeResponse{}
	if err := json.NewDecoder(res.Body).Decode(exchange); err != nil {
		return nil, xerrors.WithStack(err)
	}

	return exchange, nil
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
