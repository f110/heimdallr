package localproxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
)

type TokenExchangeResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type TokenClient struct {
	tokenFilename string
}

func NewTokenClient(tokenFilename string) *TokenClient {
	return &TokenClient{tokenFilename: tokenFilename}
}

func (c *TokenClient) GetToken() (string, error) {
	return c.readToken()
}

func (c *TokenClient) RequestToken(endpoint string) (string, error) {
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
	if err := OpenBrowser(u.String()); err != nil {
		return "", xerrors.Errorf(": %v", err)
	}

	code, err := c.getCode()
	if err != nil {
		return "", xerrors.Errorf(": %v", err)
	}
	token, err := c.exchangeToken(endpoint, code, verifier)
	if err != nil {
		return "", xerrors.Errorf(": %v", err)
	}

	if err := c.saveToken(token); err != nil {
		return "", xerrors.Errorf(": %v", err)
	}

	return token, nil
}

func (c *TokenClient) readToken() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", xerrors.Errorf(": %v", err)
	}
	f, err := os.Open(filepath.Join(home, ".lagrangian", c.tokenFilename))
	if os.IsNotExist(err) {
		return "", nil
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return "", xerrors.Errorf(": %v", err)
	}

	return string(b), nil
}

func (c *TokenClient) saveToken(token string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	_, err = os.Stat(filepath.Join(home, ".lagrangian"))
	if os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Join(home, ".lagrangian"), 0755); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}
	f, err := os.Create(filepath.Join(home, ".lagrangian", c.tokenFilename))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	defer f.Close()
	f.WriteString(token)

	return nil
}

func (c *TokenClient) exchangeToken(endpoint, code, codeVerifier string) (string, error) {
	v := &url.Values{}
	v.Set("code", code)
	v.Set("code_verifier", codeVerifier)
	req, err := http.NewRequest(http.MethodGet, endpoint+"/exchange?"+v.Encode(), nil)
	if err != nil {
		return "", xerrors.Errorf(": %v", err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	res, err := client.Do(req)
	if err != nil {
		return "", xerrors.Errorf(": %v", err)
	}
	if res.StatusCode != http.StatusOK {
		log.Print(res.Status)
		return "", xerrors.New("localproxy: failure exchange token")
	}

	exchange := &TokenExchangeResponse{}
	if err := json.NewDecoder(res.Body).Decode(exchange); err != nil {
		return "", xerrors.Errorf(": %v", err)
	}

	return exchange.AccessToken, nil
}

func (c *TokenClient) getCode() (string, error) {
	u, err := url.Parse(ClientRedirectUrl)
	if err != nil {
		return "", xerrors.Errorf(": %v", err)
	}

	result := make(chan string)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		result <- req.URL.Query().Get("code")
		io.WriteString(w, `success`)
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

func (c *TokenClient) newVerifier() string {
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(buf)
}

func (c *TokenClient) challenge(verifier string) string {
	s := sha256.New()
	s.Write([]byte(verifier))
	return base64.StdEncoding.EncodeToString(s.Sum(nil))
}
