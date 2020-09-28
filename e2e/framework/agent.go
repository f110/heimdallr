package framework

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/session"
)

type Agents struct {
	resolver     *resolver
	tlsConfig    *tls.Config
	sessionStore *session.SecureCookieStore

	mu         sync.Mutex
	agentCache map[string]*Agent
}

func NewAgents(domain string, ca *x509.Certificate, sessionStore *session.SecureCookieStore) *Agents {
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
		agentCache: make(map[string]*Agent),
	}
}

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

type Agent struct {
	client  *http.Client
	cookies []*http.Cookie

	lastResponse *http.Response
	lastErr      error
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
	sess := session.New(id)
	return &Agent{
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

func (a *Agents) DecodeCookieValue(name, value string) (*session.Session, error) {
	return a.sessionStore.DecodeValue(name, value)
}

func (a *Agent) Get(m *Matcher, u string) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		m.lastHttpErr = err
		return
	}
	if len(a.cookies) > 0 {
		for _, v := range a.cookies {
			req.AddCookie(v)
		}
	}

	res, err := a.client.Do(req)
	m.lastResponse = res
	m.lastHttpErr = err
	m.done = true

	a.lastResponse = res
	a.lastErr = err
}

func (a *Agent) Post(m *Matcher, u, body string) {
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(body))
	if err != nil {
		m.lastHttpErr = err
		return
	}
	if len(a.cookies) > 0 {
		for _, v := range a.cookies {
			req.AddCookie(v)
		}
	}

	res, err := a.client.Do(req)
	m.lastResponse = res
	m.lastHttpErr = err
	m.done = true

	a.lastResponse = res
	a.lastErr = err
}

func (a *Agent) FollowRedirect(m *Matcher) error {
	if a.lastResponse == nil {
		return xerrors.New("Agent does not have any response. Probably, test suite's bug.")
	}
	u, err := a.lastResponse.Location()
	if err != nil {
		m.lastResponse = nil
		m.lastHttpErr = err
		a.lastResponse = nil
		a.lastErr = err
		return err
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		m.lastResponse = nil
		m.lastHttpErr = err
		a.lastResponse = nil
		a.lastErr = err
		return err
	}
	if len(a.cookies) > 0 {
		for _, v := range a.cookies {
			req.AddCookie(v)
		}
	}

	m.lastResponse, m.lastHttpErr = a.client.Do(req)
	a.lastResponse = m.lastResponse
	a.lastErr = m.lastHttpErr
	if m.lastHttpErr != nil {
		return m.lastHttpErr
	}

	return nil
}

func (a *Agent) ParseLastResponseBody(in interface{}) error {
	return json.NewDecoder(a.lastResponse.Body).Decode(in)
}

func (a *Agent) SaveCookie() {
	a.cookies = a.lastResponse.Cookies()
}
