package config

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"sigs.k8s.io/yaml"
)

const (
	EmbedEtcdUrlFilename    = "embed_etcd_url"
	SessionTypeSecureCookie = "secure_cookie"
	SessionTypeMemcached    = "memcached"
	TemplateLoaderShotgun   = "shotgun"
	TemplateLoaderEmbed     = "embed"
)

var (
	ErrRoleNotFound = xerrors.New("config: role not found")
)

type Config struct {
	General          *General          `json:"general"`
	IdentityProvider *IdentityProvider `json:"identity_provider,omitempty"`
	Datastore        *Datastore        `json:"datastore"`
	Logger           *Logger           `json:"logger,omitempty"`
	FrontendProxy    *FrontendProxy    `json:"frontend_proxy,omitempty"`
	Dashboard        *Dashboard        `json:"dashboard,omitempty"`
}

type General struct {
	Enable               bool                  `json:"enable"`
	Debug                bool                  `json:"debug,omitempty"`
	Bind                 string                `json:"bind,omitempty"`
	ServerName           string                `json:"server_name,omitempty"`
	CertFile             string                `json:"cert_file,omitempty"`
	KeyFile              string                `json:"key_file,omitempty"`
	RoleFile             string                `json:"role_file,omitempty"`
	ProxyFile            string                `json:"proxy_file,omitempty"`
	CertificateAuthority *CertificateAuthority `json:"certificate_authority"`
	RootUsers            []string              `json:"root_users,omitempty"`

	Roles    []Role     `json:"-"`
	Backends []*Backend `json:"-"`

	mu                sync.RWMutex        `json:"-"`
	hostnameToBackend map[string]*Backend `json:"-"`
	roleNameToRole    map[string]Role     `json:"-"`

	Certificate   tls.Certificate `json:"-"`
	AuthEndpoint  string          `json:"-"`
	TokenEndpoint string          `json:"-"`
}

type CertificateAuthority struct {
	CertFile         string `json:"cert_file"`
	KeyFile          string `json:"key_file"`
	Organization     string `json:"organization"`
	OrganizationUnit string `json:"organization_unit"`
	Country          string `json:"country"`

	Subject     pkix.Name         `json:"-"`
	Certificate *x509.Certificate `json:"-"`
	PrivateKey  crypto.PrivateKey `json:"-"`
	CertPool    *x509.CertPool    `json:"-"`
}

type IdentityProvider struct {
	Provider         string   `json:"provider"` // "google", "okta" or "azure"
	ClientId         string   `json:"client_id"`
	ClientSecretFile string   `json:"client_secret_file"`
	ExtraScopes      []string `json:"extra_scopes"`
	Domain           string   `json:"domain,omitempty"` // for Okta and AzureAD
	RedirectUrl      string   `json:"redirect_url"`

	ClientSecret string `json:"-"`
}

type Datastore struct {
	RawUrl    string `json:"url"`
	DataDir   string `json:"data_dir,omitempty"`  // use only embed etcd
	Namespace string `json:"namespace,omitempty"` // use only etcd

	Url        *url.URL         `json:"-"`
	Embed      bool             `json:"-"`
	EtcdUrl    *url.URL         `json:"-"`
	etcdClient *clientv3.Client `json:"-"`
}

type Logger struct {
	Level    string `json:"level"`
	Encoding string `json:"encoding"` // json or console
}

type Role struct {
	Name        string    `json:"name"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Bindings    []Binding `json:"bindings"`
}

type Binding struct {
	Backend    string `json:"backend"`    // Backend is Backend.Name
	Permission string `json:"permission"` // Permission is Permission.Name
}

type Backend struct {
	Name            string        `json:"name"` // Name is an identifier
	Upstream        string        `json:"upstream"`
	Permissions     []*Permission `json:"permissions"`
	WebHook         string        `json:"webhook,omitempty"` // name of webhook provider (e.g. github)
	WebHookPath     []string      `json:"webhook_path,omitempty"`
	Agent           bool          `json:"agent,omitempty"`
	AllowAsRootUser bool          `json:"allow_as_root_user,omitempty"`

	Url           *url.URL    `json:"-"`
	Socket        bool        `json:"-"`
	WebHookRouter *mux.Router `json:"-"`
}

type Permission struct {
	Name      string     `json:"name"` // Name is an identifier
	Locations []Location `json:"locations"`

	router *mux.Router `json:"-"`
}

type Location struct {
	Any     string `json:"any,omitempty"`
	Get     string `json:"get,omitempty"`
	Post    string `json:"post,omitempty"`
	Put     string `json:"put,omitempty"`
	Delete  string `json:"delete,omitempty"`
	Head    string `json:"head,omitempty"`
	Connect string `json:"connect,omitempty"`
	Options string `json:"options,omitempty"`
	Trace   string `json:"trace,omitempty"`
	Patch   string `json:"patch,omitempty"`
}

type FrontendProxy struct {
	SigningSecretKeyFile    string   `json:"signing_secret_key_file"`
	GithubWebHookSecretFile string   `json:"github_webhook_secret_file"`
	AccessLogFile           string   `json:"access_log"`
	ExpectCT                bool     `json:"expect_ct"`
	Session                 *Session `json:"session,omitempty"`

	Certificate         tls.Certificate   `json:"-"`
	SigningPrivateKey   *ecdsa.PrivateKey `json:"-"`
	SigningPublicKey    ecdsa.PublicKey   `json:"-"`
	GithubWebhookSecret []byte            `json:"-"`
	AccessLog           *os.File          `json:"-"`
}

type Session struct {
	Type    string   `json:"type"` // secure_cookie or memcached
	KeyFile string   `json:"key_file,omitempty"`
	Servers []string `json:"servers,omitempty"`

	HashKey  []byte `json:"-"`
	BlockKey []byte `json:"-"`
}

type Dashboard struct {
	Enable   bool      `json:"enable"`
	Bind     string    `json:"bind,omitempty"`
	Template *Template `json:"template,omitempty"`
}

type Template struct {
	Loader string `json:"loader"` // shotgun or embed
	Dir    string `json:"dir"`
}

func (d *Dashboard) Inflate(dir string) error {
	return d.Template.inflate(dir)
}

func (t *Template) inflate(dir string) error {
	if t.Dir != "" && t.Loader == TemplateLoaderShotgun {
		t.Dir = filepath.Join(dir, t.Dir)
	}
	return nil
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
		ca.CertPool = x509.NewCertPool()
		ca.CertPool.AddCert(cert)

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

	ca.Subject = pkix.Name{
		Organization:       []string{ca.Organization},
		OrganizationalUnit: []string{ca.OrganizationUnit},
		Country:            []string{ca.Country},
		CommonName:         "Lagrangian Proxy CA",
	}

	return nil
}

func (f *FrontendProxy) Inflate(dir string) error {
	if f.SigningSecretKeyFile != "" {
		privateKey, err := readPrivateKey(absPath(f.SigningSecretKeyFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		f.SigningPrivateKey = privateKey
		f.SigningPublicKey = privateKey.PublicKey
	}
	if f.GithubWebHookSecretFile != "" {
		b, err := ioutil.ReadFile(absPath(f.GithubWebHookSecretFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		f.GithubWebhookSecret = b
	}
	if f.Session != nil {
		if err := f.Session.Inflate(dir); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}
	if f.AccessLogFile != "" {
		f.AccessLogFile = absPath(f.AccessLogFile, dir)
		file, err := os.OpenFile(f.AccessLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		f.AccessLog = file
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

func (g *General) GetBackend(name string) (*Backend, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, v := range g.Backends {
		if v.Name == name {
			return v, true
		}
	}

	return nil, false
}

func (g *General) GetAllBackends() []*Backend {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.Backends
}

func (g *General) GetAllRoles() []Role {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.Roles
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
	if g.CertFile != "" && g.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(absPath(g.CertFile, dir), absPath(g.KeyFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		g.Certificate = cert
	}
	if g.RoleFile != "" {
		roles := make([]Role, 0)
		b, err := ioutil.ReadFile(absPath(g.RoleFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if err := yaml.Unmarshal(b, &roles); err != nil {
			return xerrors.Errorf(": %v", err)
		}
		g.Roles = roles
	}
	if g.ProxyFile != "" {
		backends := make([]*Backend, 0)
		b, err := ioutil.ReadFile(absPath(g.ProxyFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if err := yaml.Unmarshal(b, &backends); err != nil {
			return xerrors.Errorf(": %v", err)
		}
		g.Backends = backends
	}
	if g.CertificateAuthority != nil {
		if err := g.CertificateAuthority.inflate(dir); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	g.AuthEndpoint = fmt.Sprintf("https://%s/auth", g.ServerName)
	g.TokenEndpoint = fmt.Sprintf("https://%s/token", g.ServerName)

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

	if u.Scheme == "tcp" {
		b.Socket = true
	}

	if len(b.WebHookPath) > 0 {
		mux := mux.NewRouter()
		for _, v := range b.WebHookPath {
			mux.PathPrefix(v)
		}
		b.WebHookRouter = mux
	}

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

func readPrivateKey(path string) (*ecdsa.PrivateKey, error) {
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
	case "PRIVATE KEY":
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}

		switch v := privateKey.(type) {
		case *ecdsa.PrivateKey:
			return v, nil
		default:
			return nil, xerrors.New("config: invalid private key type")
		}
	default:
		return nil, xerrors.Errorf("config: Unknown Type: %s", block.Type)
	}
}
