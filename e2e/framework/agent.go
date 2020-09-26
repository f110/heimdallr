package framework

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type Agents struct {
	resolver  *resolver
	tlsConfig *tls.Config
}

func NewAgents(domain string, ca *x509.Certificate) *Agents {
	s := strings.SplitN(domain, ":", 2)
	certPool, _ := x509.SystemCertPool()
	if ca != nil {
		certPool.AddCert(ca)
	}

	return &Agents{
		resolver: &resolver{domain: s[0]},
		tlsConfig: &tls.Config{
			RootCAs: certPool,
		},
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

type Agent struct {
	resolver *resolver
	client   *http.Client
}

func (a *Agents) Unauthorized() *Agent {
	return &Agent{
		resolver: a.resolver,
		client: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: a.tlsConfig.Clone(),
			},
		},
	}
}

func (a *Agent) Get(m *Matcher, u string) {
	p, err := url.Parse(u)
	if err != nil {
		m.lastHttpErr = err
		return
	}
	hostname := p.Hostname()
	addrs, err := a.resolver.LookupHost(p.Hostname())
	if err != nil {
		m.lastHttpErr = err
		return
	}
	p.Host = addrs[0] + ":" + p.Port()
	req, err := http.NewRequest(http.MethodGet, p.String(), nil)
	if err != nil {
		m.lastHttpErr = err
		return
	}
	req.Host = hostname
	a.client.Transport.(*http.Transport).TLSClientConfig.ServerName = hostname

	res, err := a.client.Do(req)
	m.lastResponse = res
	m.lastHttpErr = err
	m.done = true
	return
}
