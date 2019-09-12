package config

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/clientv3/namespace"
	"github.com/gorilla/mux"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"
)

const (
	EmbedEtcdUrlFilename    = "embed_etcd_url"
	SessionTypeSecureCookie = "secure_cookie"
)

var (
	ErrRoleNotFound = xerrors.New("config: role not found")
)

type Config struct {
	General          *General          `yaml:"general"`
	IdentityProvider *IdentityProvider `yaml:"identity_provider"`
	Datastore        *Datastore        `yaml:"datastore"`
	Logger           *Logger           `yaml:"logger"`
	FrontendProxy    *FrontendProxy    `yaml:"frontend_proxy"`
}

type General struct {
	RoleFile             string                `yaml:"role_file"`
	ProxyFile            string                `yaml:"proxy_file"`
	CertificateAuthority *CertificateAuthority `yaml:"certificate_authority"`

	Roles    []Role     `yaml:"-"`
	Backends []*Backend `yaml:"-"`

	mu                sync.RWMutex        `yaml:"-"`
	hostnameToBackend map[string]*Backend `yaml:"-"`
	roleNameToRole    map[string]Role     `yaml:"-"`
}

type CertificateAuthority struct {
	CertFile         string `yaml:"cert_file"`
	KeyFile          string `yaml:"key_file"`
	Organization     string `yaml:"organization"`
	OrganizationUnit string `yaml:"organization_unit"`
	Country          string `yaml:"country"`

	Certificate *x509.Certificate `yaml:"-"`
	PrivateKey  crypto.PrivateKey `yaml:"-"`
}

type IdentityProvider struct {
	Bind             string   `yaml:"bind"`
	EndpointUrl      string   `yaml:"endpoint_url"`
	Provider         string   `yaml:"provider"`
	ClientId         string   `yaml:"client_id"`
	ClientSecretFile string   `yaml:"client_secret_file"`
	ExtraScopes      []string `yaml:"extra_scopes"`
	RedirectUrl      string   `yaml:"redirect_url"`

	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`

	ClientSecret string          `yaml:"-"`
	Certificate  tls.Certificate `yaml:"-"`
}

type Datastore struct {
	RawUrl    string `yaml:"url"`
	DataDir   string `yaml:"data_dir"`  // use only embed etcd
	Namespace string `yaml:"namespace"` // use only etcd

	Url        *url.URL         `yaml:"-"`
	Embed      bool             `yaml:"-"`
	EtcdUrl    *url.URL         `yaml:"-"`
	etcdClient *clientv3.Client `yaml:"-"`
}

type Logger struct {
	Level    string `yaml:"level"`
	Encoding string `yaml:"encoding"` // json or console
}

type Role struct {
	Name        string    `yaml:"name"`
	Title       string    `yaml:"title"`
	Description string    `yaml:"description"`
	Bindings    []Binding `yaml:"bindings"`
}

type Binding struct {
	Backend    string `yaml:"backend"`    // Backend is Backend.Name
	Permission string `yaml:"permission"` // Permission is Permission.Name
}

type Backend struct {
	Name        string        `yaml:"name"` // Name is an identifier
	Upstream    string        `yaml:"upstream"`
	Permissions []*Permission `yaml:"permissions"`

	Url *url.URL `yaml:"-"`
}

type Permission struct {
	Name      string     `yaml:"name"` // Name is an identifier
	Locations []Location `yaml:"locations"`

	router *mux.Router `yaml:"-"`
}

type Location struct {
	Any     string `yaml:"any"`
	Get     string `yaml:"get"`
	Post    string `yaml:"post"`
	Put     string `yaml:"put"`
	Delete  string `yaml:"delete"`
	Head    string `yaml:"head"`
	Connect string `yaml:"connect"`
	Options string `yaml:"options"`
	Trace   string `yaml:"trace"`
	Patch   string `yaml:"patch"`
}

type FrontendProxy struct {
	Bind                 string   `yaml:"bind"`
	CertFile             string   `yaml:"cert_file"`
	KeyFile              string   `yaml:"key_file"`
	SigningSecretKeyFile string   `yaml:"signing_secret_key_file"`
	Session              *Session `yaml:"session"`

	Certificate       tls.Certificate   `yaml:"-"`
	SigningPrivateKey crypto.PrivateKey `yaml:"-"`
}

type Session struct {
	Type    string `yaml:"type"`
	KeyFile string `yaml:"key_file"`

	HashKey  []byte `yaml:"-"`
	BlockKey []byte `yaml:"-"`
}

func (idp *IdentityProvider) Inflate(dir string) error {
	if idp.ClientSecretFile != "" {
		b, err := ioutil.ReadFile(absPath(idp.ClientSecretFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		b = bytes.TrimRight(b, "\n")
		idp.ClientSecret = string(b)
	}
	if idp.CertFile != "" && idp.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(absPath(idp.CertFile, dir), absPath(idp.KeyFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		idp.Certificate = cert
	}

	return nil
}

func (ca *CertificateAuthority) inflate(dir string) error {
	if ca.CertFile != "" && ca.KeyFile != "" {
		b, err := ioutil.ReadFile(absPath(ca.CertFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		block, _ := pem.Decode(b)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		ca.Certificate = cert

		b, err = ioutil.ReadFile(absPath(ca.KeyFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		block, _ = pem.Decode(b)
		switch block.Type {
		case "EC PRIVATE KEY":
			privateKey, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			ca.PrivateKey = privateKey
		case "RSA PRIVATE KEY":
			privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			ca.PrivateKey = privateKey
		case "PRIVATE KEY":
			privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			ca.PrivateKey = privateKey
		}
	}

	return nil
}

func (f *FrontendProxy) Inflate(dir string) error {
	if f.CertFile != "" && f.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(absPath(f.CertFile, dir), absPath(f.KeyFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		f.Certificate = cert
	}
	if f.SigningSecretKeyFile != "" {
		privateKey, err := readPrivateKey(absPath(f.SigningSecretKeyFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		f.SigningPrivateKey = privateKey
	}
	if f.Session != nil {
		if err := f.Session.Inflate(dir); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	return nil
}

func (s *Session) Inflate(dir string) error {
	switch s.Type {
	case SessionTypeSecureCookie:
		b, err := ioutil.ReadFile(absPath(s.KeyFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		b = bytes.TrimRight(b, "\n")
		keys := bytes.Split(b, []byte("\n"))
		if len(keys) != 2 {
			return xerrors.New("config: invalid cookie secret file")
		}
		s.HashKey = keys[0]
		s.BlockKey = keys[1]
	}
	return nil
}

func (p *Permission) inflate() {
	r := mux.NewRouter()
	for _, l := range p.Locations {
		l.AddRouter(r)
	}
	p.router = r
}

func (g *General) GetBackendByHostname(hostname string) (*Backend, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	v, ok := g.hostnameToBackend[hostname]
	return v, ok
}

// GetBackendByHost is finding Backend by Host header
func (g *General) GetBackendByHost(host string) (*Backend, bool) {
	h := host
	if strings.Contains(host, ":") {
		s := strings.SplitN(host, ":", 2)
		h = s[0]
	}

	return g.GetBackendByHostname(h)
}

func (g *General) GetRole(name string) (Role, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if v, ok := g.roleNameToRole[name]; ok {
		return v, nil
	}

	return Role{}, ErrRoleNotFound
}

func (g *General) Inflate(dir string) error {
	g.mu = sync.RWMutex{}

	if g.RoleFile != "" {
		roles := make([]Role, 0)
		f, err := os.Open(absPath(g.RoleFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if err := yaml.NewDecoder(f).Decode(&roles); err != nil {
			return xerrors.Errorf(": %v", err)
		}
		g.Roles = roles
	}
	if g.ProxyFile != "" {
		backends := make([]*Backend, 0)
		f, err := os.Open(absPath(g.ProxyFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if err := yaml.NewDecoder(f).Decode(&backends); err != nil {
			return xerrors.Errorf(": %v", err)
		}
		g.Backends = backends
	}
	if g.CertificateAuthority != nil {
		if err := g.CertificateAuthority.inflate(dir); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	return g.Load()
}

func (g *General) Load() error {
	g.hostnameToBackend = make(map[string]*Backend)
	for _, v := range g.Backends {
		if err := v.inflate(); err != nil {
			return err
		}
		g.hostnameToBackend[v.Name] = v
	}

	g.roleNameToRole = make(map[string]Role)
	for _, v := range g.Roles {
		g.roleNameToRole[v.Name] = v
	}

	return nil
}

func (d *Datastore) Inflate(dir string) error {
	if d.RawUrl != "" {
		u, err := url.Parse(d.RawUrl)
		if err != nil {
			return err
		}
		d.Url = u

		if u.Host == "embed" {
			d.Embed = true
		}
	}
	if d.DataDir != "" {
		d.DataDir = absPath(d.DataDir, dir)
	}
	if d.Namespace != "" {
		if !strings.HasSuffix(d.Namespace, "/") {
			d.Namespace += "/"
		}
	} else {
		d.Namespace = "/"
	}

	switch d.Url.Scheme {
	case "etcd":
		if d.Embed {
			if _, err := os.Stat(filepath.Join(d.DataDir, EmbedEtcdUrlFilename)); os.IsNotExist(err) {
				// first time
				l, err := net.Listen("tcp", ":0")
				if err != nil {
					return xerrors.Errorf(": %v", err)
				}
				addr := l.Addr().(*net.TCPAddr)
				if err := l.Close(); err != nil {
					return xerrors.Errorf(": %v", err)
				}

				u := &url.URL{Scheme: "http", Host: fmt.Sprintf("localhost:%d", addr.Port)}
				if err := os.MkdirAll(filepath.Join(d.DataDir), 0755); err != nil {
					return xerrors.Errorf(": %v", err)
				}
				err = ioutil.WriteFile(filepath.Join(d.DataDir, EmbedEtcdUrlFilename), []byte(u.String()), 0600)
				if err != nil {
					return xerrors.Errorf(": %v", err)
				}
				d.EtcdUrl = u
			} else {
				b, err := ioutil.ReadFile(filepath.Join(d.DataDir, EmbedEtcdUrlFilename))
				if err != nil {
					return xerrors.Errorf(": %v", err)
				}
				u, err := url.Parse(string(b))
				if err != nil {
					return xerrors.Errorf(": %v", err)
				}
				d.EtcdUrl = u
			}
		} else {
			u := new(url.URL)
			*u = *d.Url
			u.Scheme = "http"
			d.EtcdUrl = u
		}
	}

	return nil
}

func (d *Datastore) GetEtcdClient() (*clientv3.Client, error) {
	if d.etcdClient != nil {
		return d.etcdClient, nil
	}

	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{d.EtcdUrl.String()},
		DialTimeout: 1 * time.Second,
	})
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	client.KV = namespace.NewKV(client.KV, d.Namespace)
	client.Lease = namespace.NewLease(client.Lease, d.Namespace)
	client.Watcher = namespace.NewWatcher(client.Watcher, d.Namespace)
	d.etcdClient = client
	return client, nil
}

func (b *Backend) inflate() error {
	for _, p := range b.Permissions {
		p.inflate()
	}
	u, err := url.Parse(b.Upstream)
	if err != nil {
		return xerrors.Errorf("%s: %v", b.Name, err)
	}
	b.Url = u

	return nil
}

func (b *Backend) MatchList(req *http.Request) map[string]struct{} {
	allMatched := make(map[string]struct{})
	match := &mux.RouteMatch{}
	for _, p := range b.Permissions {
		if p.router.Match(req, match) {
			allMatched[p.Name] = struct{}{}
		}
	}

	return allMatched
}

func (l *Location) AddRouter(r *mux.Router) {
	if l.Any != "" {
		r.PathPrefix(l.Any)
	}
	if l.Get != "" {
		r.Methods(http.MethodGet).PathPrefix(l.Get)
	}
	if l.Post != "" {
		r.Methods(http.MethodPost).PathPrefix(l.Post)
	}
	if l.Put != "" {
		r.Methods(http.MethodPut).PathPrefix(l.Put)
	}
	if l.Delete != "" {
		r.Methods(http.MethodDelete).PathPrefix(l.Delete)
	}
	if l.Head != "" {
		r.Methods(http.MethodHead).PathPrefix(l.Head)
	}
	if l.Connect != "" {
		r.Methods(http.MethodConnect).PathPrefix(l.Connect)
	}
	if l.Options != "" {
		r.Methods(http.MethodOptions).PathPrefix(l.Options)
	}
	if l.Trace != "" {
		r.Methods(http.MethodTrace).PathPrefix(l.Trace)
	}
	if l.Patch != "" {
		r.Methods(http.MethodPatch).PathPrefix(l.Patch)
	}
}

func absPath(path, dir string) string {
	if strings.HasPrefix(path, "./") {
		a, err := filepath.Abs(filepath.Join(dir, path))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return ""
		}
		return a
	}
	return path
}

func readPrivateKey(path string) (crypto.PrivateKey, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	block, _ := pem.Decode(b)
	switch block.Type {
	case "EC PRIVATE KEY":
		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}
		return privateKey, nil
	case "RSA PRIVATE KEY":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}
		return privateKey, nil
	case "PRIVATE KEY":
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}
		return privateKey, nil
	default:
		return nil, xerrors.Errorf("config: Unknown Type: %s", block.Type)
	}
}
