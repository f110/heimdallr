package framework

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"github.com/stretchr/testify/assert"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"go.f110.dev/heimdallr/pkg/auth/authn"
	"go.f110.dev/heimdallr/pkg/authproxy"
	"go.f110.dev/heimdallr/pkg/config/userconfig"
	"go.f110.dev/heimdallr/pkg/rpc"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
	"go.f110.dev/heimdallr/pkg/session"
	"go.f110.dev/heimdallr/pkg/testing/btesting"
)

type resolver struct {
	domain string
}

func (r *resolver) LookupHost(host string) ([]string, error) {
	h := host
	if strings.Contains(host, ":") {
		s := strings.SplitN(host, ":", 2)
		h = s[0]
	}
	if strings.HasSuffix(h, r.domain) {
		return []string{"127.0.0.1"}, nil
	}

	return net.LookupHost(host)
}

type transport struct {
	sess         *session.Session
	sessionStore *session.SecureCookieStore
	resolver     *resolver
	*http.Transport
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	hostname := req.URL.Hostname()
	addrs, err := t.resolver.LookupHost(hostname)
	if err != nil {
		return nil, err
	}
	if strings.Contains(req.URL.Host, ":") {
		req.URL.Host = addrs[0] + ":" + req.URL.Port()
	} else {
		req.URL.Host = addrs[0]
	}
	t.Transport.TLSClientConfig.ServerName = hostname

	if t.sessionStore != nil && t.sess != nil {
		cookie, err := t.sessionStore.Cookie(t.sess)
		if err != nil {
			return nil, err
		}
		req.AddCookie(cookie)
	}

	return t.Transport.RoundTrip(req)
}

type Agents struct {
	resolver     *resolver
	tlsConfig    *tls.Config
	sessionStore *session.SecureCookieStore

	mu         sync.Mutex
	agentCache map[string]*Agent

	rpcPort        int
	signPrivateKey *ecdsa.PrivateKey
}

func NewAgents(
	domain string,
	ca *x509.Certificate,
	sessionStore *session.SecureCookieStore,
	rpcPort int,
	signPrivateKey *ecdsa.PrivateKey,
) *Agents {
	s := strings.SplitN(domain, ":", 2)
	certPool, _ := x509.SystemCertPool()
	if ca != nil {
		certPool.AddCert(ca)
	}

	return &Agents{
		resolver:     &resolver{domain: s[0]},
		sessionStore: sessionStore,
		tlsConfig: &tls.Config{
			RootCAs: certPool,
		},
		agentCache:     make(map[string]*Agent),
		rpcPort:        rpcPort,
		signPrivateKey: signPrivateKey,
	}
}

func (a *Agents) Unauthorized() *Agent {
	return &Agent{
		client: &http.Client{
			CheckRedirect: func(_req *http.Request, _via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &transport{
				resolver: a.resolver,
				Transport: &http.Transport{
					Proxy: http.ProxyFromEnvironment,
					DialContext: (&net.Dialer{
						Timeout:   30 * time.Second,
						KeepAlive: 30 * time.Second,
						DualStack: true,
					}).DialContext,
					ForceAttemptHTTP2:     true,
					MaxIdleConns:          100,
					IdleConnTimeout:       90 * time.Second,
					TLSHandshakeTimeout:   10 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
					TLSClientConfig:       a.tlsConfig.Clone(),
				},
			},
		},
	}
}

// Authorized returns the agent for authorized user.
// This agent uses the cookie secret.
func (a *Agents) Authorized(id string) *Agent {
	a.mu.Lock()
	defer a.mu.Unlock()

	if v, ok := a.agentCache[id]; ok {
		return v
	}

	sess := session.New(id)
	newAgent := &Agent{
		client: &http.Client{
			CheckRedirect: func(_req *http.Request, _via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &transport{
				sess:         sess,
				sessionStore: a.sessionStore,
				resolver:     a.resolver,
				Transport: &http.Transport{
					Proxy: http.ProxyFromEnvironment,
					DialContext: (&net.Dialer{
						Timeout:   30 * time.Second,
						KeepAlive: 30 * time.Second,
						DualStack: true,
					}).DialContext,
					ForceAttemptHTTP2:     true,
					MaxIdleConns:          100,
					IdleConnTimeout:       90 * time.Second,
					TLSHandshakeTimeout:   10 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
					TLSClientConfig:       a.tlsConfig.Clone(),
				},
			},
		},
	}
	a.agentCache[id] = newAgent
	return newAgent
}

// User returns the agent for user.
// This agent is not authorized initially.
// If called by same id, then returns the same agent.
// User is caching the agent, Authorized creates the agent by each call.
func (a *Agents) User(id string) *Agent {
	a.mu.Lock()
	defer a.mu.Unlock()

	if v, ok := a.agentCache[id]; ok {
		return v
	}

	newAgent := &Agent{
		client: &http.Client{
			CheckRedirect: func(_req *http.Request, _via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &transport{
				resolver: a.resolver,
				Transport: &http.Transport{
					Proxy: http.ProxyFromEnvironment,
					DialContext: (&net.Dialer{
						Timeout:   30 * time.Second,
						KeepAlive: 30 * time.Second,
						DualStack: true,
					}).DialContext,
					ForceAttemptHTTP2:     true,
					MaxIdleConns:          100,
					IdleConnTimeout:       90 * time.Second,
					TLSHandshakeTimeout:   10 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
					TLSClientConfig:       a.tlsConfig.Clone(),
				},
			},
		},
	}
	a.agentCache[id] = newAgent
	return newAgent
}

func (a *Agents) RPCClient(id string) *rpcclient.ClientWithUserToken {
	cred := credentials.NewTLS(&tls.Config{ServerName: rpc.ServerHostname, RootCAs: a.tlsConfig.RootCAs})
	conn, err := grpc.Dial(
		fmt.Sprintf("127.0.0.1:%d", a.rpcPort),
		grpc.WithTransportCredentials(cred),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: time.Second, PermitWithoutStream: true}),
		grpc.WithStreamInterceptor(retry.StreamClientInterceptor()),
		grpc.WithUnaryInterceptor(retry.UnaryClientInterceptor()),
	)
	if err != nil {
		return nil
	}

	claim := jwt.NewWithClaims(jwt.SigningMethodES256, &authn.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        RootUserId,
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(authproxy.TokenExpiration).Unix(),
		},
	})
	token, err := claim.SignedString(a.signPrivateKey)
	if err != nil {
		return nil
	}

	return rpcclient.NewClientWithUserToken(conn).WithToken(token)
}

func (a *Agents) DecodeCookieValue(value string) (*session.Session, error) {
	return a.sessionStore.DecodeValue(value)
}

type Agent struct {
	client  *http.Client
	cookies []*http.Cookie

	lastResponse *http.Response
	lastErr      error

	tunnel      *Tunnel
	tempDirOnce sync.Once
	tempDir     string
}

func (a *Agent) Get(m *btesting.Matcher, u string) bool {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		m.SetLastResponse(nil, err)
		return false
	}
	if len(a.cookies) > 0 {
		for _, v := range a.cookies {
			req.AddCookie(v)
		}
	}

	res, err := a.client.Do(req)
	m.SetLastResponse(res, err)
	m.Done()

	a.lastResponse = res
	a.lastErr = err

	return true
}

func (a *Agent) Post(m *btesting.Matcher, u, body string) bool {
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(body))
	if err != nil {
		m.SetLastResponse(nil, err)
		return false
	}
	if len(body) > 0 {
		req.Header.Set("Content-type", "application/x-www-form-urlencoded")
	}
	if len(a.cookies) > 0 {
		for _, v := range a.cookies {
			req.AddCookie(v)
		}
	}

	res, err := a.client.Do(req)
	m.SetLastResponse(res, err)
	m.Done()

	a.lastResponse = res
	a.lastErr = err

	if err != nil {
		return false
	}

	return true
}

func (a *Agent) FollowRedirect(m *btesting.Matcher) error {
	if a.lastResponse == nil {
		return xerrors.New("Agent does not have any response. Probably, test suite's bug.")
	}
	u, err := a.lastResponse.Location()
	if err != nil {
		m.SetLastResponse(nil, err)
		a.lastResponse = nil
		a.lastErr = err
		return err
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		m.SetLastResponse(nil, err)
		a.lastResponse = nil
		a.lastErr = err
		return err
	}
	if len(a.cookies) > 0 {
		for _, v := range a.cookies {
			req.AddCookie(v)
		}
	}

	res, err := a.client.Do(req)
	m.SetLastResponse(res, err)
	a.lastResponse = res
	a.lastErr = err
	if err != nil {
		return err
	}

	return nil
}

func (a *Agent) ParseLastResponseBody(in interface{}) error {
	return json.NewDecoder(a.lastResponse.Body).Decode(in)
}

func (a *Agent) SaveCookie() {
	if a.lastResponse != nil {
		a.cookies = a.lastResponse.Cookies()
	}
}

func (a *Agent) Tunnel(m *btesting.Matcher) *Tunnel {
	if a.tunnel != nil {
		return a.tunnel
	}

	a.tempDirOnce.Do(func() {
		tmpDir := m.T.TempDir()
		a.tempDir = tmpDir

		err := os.WriteFile(filepath.Join(a.tempDir, "open-url"), []byte(openURLCommandScript), 0755)
		if err != nil {
			a.lastErr = err
			return
		}
	})

	a.tunnel = NewTunnel(a.tempDir)
	return a.tunnel
}

const openURLCommandScript = `#!/usr/bin/env bash
echo $1 > $(dirname $0)/url.txt`

type Tunnel struct {
	Homedir string
	Buf     *bytes.Buffer

	bin     string
	cmd     *exec.Cmd
	urlFile string
}

func NewTunnel(homedir string) *Tunnel {
	return &Tunnel{Homedir: homedir, bin: *tunnelBinaryPath}
}

func (t *Tunnel) Init() bool {
	cmd := exec.Command(t.bin, "init")
	cmd.Env = []string{"HOME=" + t.Homedir}
	if *verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return false
	}

	return true
}

func (t *Tunnel) LoadCert(c []byte) bool {
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: c}); err != nil {
		return false
	}
	if err := os.WriteFile(filepath.Join(t.Homedir, "cert.crt"), buf.Bytes(), 0644); err != nil {
		return false
	}
	cmd := exec.Command(t.bin, "init", "--certificate", filepath.Join(t.Homedir, "cert.crt"))
	cmd.Env = []string{"HOME=" + t.Homedir}
	if *verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return false
	}

	return true
}

func (t *Tunnel) Proxy(m *btesting.Matcher, host, resolver string, body io.Reader) bool {
	if t.cmd != nil {
		return false
	}

	buf := new(bytes.Buffer)
	r, w := io.Pipe()
	receiveNotifyCh := make(chan struct{})
	go func() {
		var once sync.Once
		b := make([]byte, 1024)
		for {
			n, err := r.Read(b)
			if n > 0 {
				once.Do(func() {
					close(receiveNotifyCh)
				})
				buf.Write(b[:n])
			}
			if err == io.EOF {
				break
			} else if err != nil {
				break
			}
		}
	}()

	cmd := exec.Command(t.bin,
		"--override-open-url-command",
		filepath.Join(t.Homedir, "open-url"),
		"--resolver",
		resolver,
		"proxy",
		"--insecure",
		host,
	)
	cmd.Env = []string{"HOME=" + t.Homedir}
	cmd.Stdin = body
	cmd.Stdout = w
	if *verbose {
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Start(); err != nil {
		return false
	}
	t.cmd = cmd
	t.Buf = buf
	t.urlFile = filepath.Join(t.Homedir, "url.txt")
	openBrowserNotifyCh := make(chan struct{})
	doneCh := make(chan struct{})
	defer close(doneCh)
	go func() {
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()

		for {
			select {
			case <-tick.C:
				info, err := os.Stat(t.urlFile)
				if err != nil {
					continue
				}
				if info.Size() > 0 {
					close(openBrowserNotifyCh)
					return
				}
			case <-doneCh:
				return
			}
		}
	}()

	select {
	case <-time.After(1 * time.Second):
		return false
	case <-receiveNotifyCh:
		return true
	case <-openBrowserNotifyCh:
		return true
	}
}

func (t *Tunnel) OpenURL(m *btesting.Matcher) bool {
	if t.urlFile == "" {
		return assert.Fail(m.T, "Not open URL")
	}
	buf, err := os.ReadFile(t.urlFile)
	assert.NoError(m.T, err)
	return assert.Greater(m.T, len(buf), 1)
}

func (t *Tunnel) GetFirstCertificate(m *btesting.Matcher, rpcClient *rpcclient.ClientWithUserToken) []byte {
	certs, err := rpcClient.ListCert()
	m.Must(err)
	if len(certs) != 1 {
		m.Failf("Unexpected the number of certificates: %d", len(certs))
	}
	serialNumber := big.NewInt(0)
	serialNumber.SetBytes(certs[0].SerialNumber)
	cert, err := rpcClient.GetCert(serialNumber)
	m.Must(err)

	return cert.Certificate
}

func (t *Tunnel) CSR(m *btesting.Matcher) string {
	buf, err := os.ReadFile(filepath.Join(t.Homedir, userconfig.Directory, userconfig.CSRFilename))
	if err != nil {
		m.Failf("Failed CSR file: %v", err)
	}

	return string(buf)
}

func (t *Tunnel) OpeningURL() string {
	buf, err := os.ReadFile(filepath.Join(t.Homedir, "url.txt"))
	if err != nil {
		return ""
	}

	return string(bytes.TrimSpace(buf))
}

func (t *Tunnel) Stop() {
	if t.cmd == nil {
		return
	}

	t.cmd.Process.Signal(syscall.SIGTERM)
}

func (t *Tunnel) WaitGettingToken(timeout time.Duration) bool {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	end := time.After(timeout)
	for {
		select {
		case <-tick.C:
			info, err := os.Stat(filepath.Join(t.Homedir, userconfig.Directory, userconfig.TokenFilename))
			if err != nil {
				continue
			}
			if info.Size() > 0 {
				return true
			}
		case <-end:
			return false
		}
	}
}
