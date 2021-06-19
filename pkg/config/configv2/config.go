package configv2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"go.etcd.io/etcd/v3/clientv3"
	"go.etcd.io/etcd/v3/clientv3/namespace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/pkg/cert/vault"
	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/k8s"
	"go.f110.dev/heimdallr/pkg/rpc"
)

const (
	EmbedEtcdUrlFilename = "embed_etcd_url"
)

var SystemRole = &Role{
	Name: "system:proxy",
	Bindings: []*Binding{
		{RPC: "system:proxy"},
	},
	System: true,
}
var SystemRPCPermission = &RPCPermission{
	Name: "system:proxy",
	Allow: []string{
		"proxy.rpc.certificateauthority.watchrevokedcert",
		"proxy.rpc.certificateauthority.newservercert",
		"proxy.rpc.certificateauthority.getrevokedlist",
		"proxy.rpc.cluster.defragmentdatastore",
		"proxy.rpc.authority.signrequest",
		"proxy.rpc.authority.getpublickey",
	},
}

type Config struct {
	AccessProxy          *AccessProxy          `json:"access_proxy,omitempty"`
	AuthorizationEngine  *AuthorizationEngine  `json:"authorization_engine,omitempty"`
	RPCServer            *RPCServer            `json:"rpc_server,omitempty"`
	Dashboard            *Dashboard            `json:"dashboard,omitempty"`
	IdentityProvider     *IdentityProvider     `json:"identity_provider,omitempty"`
	Datastore            *Datastore            `json:"datastore,omitempty"`
	CertificateAuthority *CertificateAuthority `json:"certificate_authority,omitempty"`
	Logger               *Logger               `json:"logger,omitempty"`
}

type AccessProxy struct {
	ProxyFile string `json:"proxy_file,omitempty"`

	HTTP       *AuthProxyHTTP `json:"http,omitempty"`
	RPCServer  string         `json:"rpc_server,omitempty"`
	Credential *Credential    `json:"credential,omitempty"`

	mu       sync.RWMutex
	Backends []*Backend `json:"-"`

	hostnameToBackend map[string]*Backend
	nameToBackend     map[string]*Backend
	watcher           *k8s.VolumeWatcher

	AuthEndpoint   string `json:"-"`
	TokenEndpoint  string `json:"-"`
	ServerNameHost string `json:"-"`
}

type AuthorizationEngine struct {
	RoleFile          string   `json:"role_file,omitempty"`
	RPCPermissionFile string   `json:"rpc_permission_file,omitempty"`
	RootUsers         []string `json:"root_users,omitempty"`

	mu                  sync.RWMutex
	Roles               []*Role          `json:"-"`
	RPCPermissions      []*RPCPermission `json:"-"`
	roleNameToRole      map[string]*Role
	nameToRpcPermission map[string]*RPCPermission
	watcher             *k8s.VolumeWatcher
}

type CertificateAuthority struct {
	Local *CertificateAuthorityLocal `json:"local,omitempty"`
	Vault *CertificateAuthorityVault `json:"vault,omitempty"`

	CertPool    *x509.CertPool    `json:"-"`
	Certificate *x509.Certificate `json:"-"`
}

type CertificateAuthorityLocal struct {
	CertFile         string `json:"cert_file"`
	KeyFile          string `json:"key_file"`
	Organization     string `json:"organization"`
	OrganizationUnit string `json:"organization_unit"`
	Country          string `json:"country"`

	Subject    pkix.Name         `json:"-"`
	PrivateKey crypto.PrivateKey `json:"-"`
}

type CertificateAuthorityVault struct {
	Addr  string `json:"addr"`
	Token string `json:"token"`
	Role  string `json:"role"`

	Dir string `json:"-"`
}

type Credential struct {
	SigningPrivateKeyFile   string `json:"signing_private_key_file,omitempty"`
	InternalTokenFile       string `json:"internal_token_file,omitempty"`
	GithubWebHookSecretFile string `json:"github_webhook_secret_file,omitempty"`

	SigningPrivateKey   *ecdsa.PrivateKey `json:"-"`
	SigningPublicKey    ecdsa.PublicKey   `json:"-"`
	InternalToken       string            `json:"-"`
	GithubWebhookSecret []byte            `json:"-"`
}

type AuthProxyHTTP struct {
	Bind            string       `json:"bind,omitempty"`
	BindHttp        string       `json:"bind_http,omitempty"`
	BindInternalApi string       `json:"bind_internal_api,omitempty"`
	ServerName      string       `json:"server_name,omitempty"`
	Certificate     *Certificate `json:"certificate,omitempty"`
	ExpectCT        bool         `json:"expect_ct,omitempty"`
	Session         *Session     `json:"session,omitempty"`
}

type RPCServer struct {
	Bind        string `json:"bind,omitempty"`
	MetricsBind string `json:"metrics_bind,omitempty"`
}

type IdentityProvider struct {
	Provider         string   `json:"provider"`         // "google", "okta", "azure" or "custom"
	Issuer           string   `json:"issuer,omitempty"` // for "custom"
	ClientId         string   `json:"client_id"`
	ClientSecretFile string   `json:"client_secret_file"`
	ExtraScopes      []string `json:"extra_scopes,omitempty"`
	Domain           string   `json:"domain,omitempty"` // for Okta and AzureAD
	RedirectUrl      string   `json:"redirect_url"`

	ClientSecret string `json:"-"`
}

type Datastore struct {
	*DatastoreEtcd  `json:"etcd,omitempty"`
	*DatastoreMySQL `json:"mysql,omitempty"`
}

type DatastoreEtcd struct {
	RawUrl     string `json:"url"`
	DataDir    string `json:"data_dir,omitempty"`  // use only embed etcd
	Namespace  string `json:"namespace,omitempty"` // use only etcd
	CACertFile string `json:"ca_cert_file,omitempty"`
	CertFile   string `json:"cert_file,omitempty"`
	KeyFile    string `json:"key_file,omitempty"`

	Url         *url.URL        `json:"-"`
	Embed       bool            `json:"-"`
	EtcdUrl     *url.URL        `json:"-"`
	Certificate tls.Certificate `json:"-"`
	CertPool    *x509.CertPool  `json:"-"`

	etcdClient *clientv3.Client
}

type DatastoreMySQL struct {
	RawUrl string `json:"url"`

	DSN *mysql.Config `json:"-"`
}

type Logger struct {
	Level    string `json:"level"`
	Encoding string `json:"encoding"` // json or console
}

type Certificate struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`

	mu          sync.RWMutex
	certificate *tls.Certificate
}

type Role struct {
	Name        string     `json:"name"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`
	Bindings    []*Binding `json:"bindings"`

	RPCMethodMatcher *rpc.MethodMatcher `json:"-"`
	System           bool               `json:"-"`
}

type Binding struct {
	RPC        string `json:"rpc,omitempty"`
	Backend    string `json:"backend,omitempty"`    // Backend is Backend.Name
	Permission string `json:"permission,omitempty"` // Permission is Permission.Name
}

type Backend struct {
	Name string         `json:"name"` // Name is an identifier
	FQDN string         `json:"fqdn,omitempty"`
	HTTP []*HTTPBackend `json:"http,omitempty"`
	// Deprecated
	Agent bool `json:"agent,omitempty"`

	Permissions   []*Permission `json:"permissions"`
	AllowRootUser bool          `json:"allow_root_user,omitempty"`
	DisableAuthn  bool          `json:"disable_authn,omitempty"`
	// MaxSessionDuration is a maximum duration before session expire for specify backend.
	// When MaxSessionDuration is not empty, OIDC authentication is required even if the user submits a client certificate.
	MaxSessionDuration *Duration `json:"max_session_duration,omitempty"`

	AllowHttp bool           `json:"allow_http,omitempty"`
	Socket    *SocketBackend `json:"socket,omitempty"`

	BackendSelector *HTTPBackendSelector `json:"-"`
	Host            string               `json:"-"`
}

type HTTPBackend struct {
	Path     string `json:"path"`
	Default  bool   `json:"default,omitempty"`
	Upstream string `json:"upstream,omitempty"`
	Insecure bool   `json:"insecure,omitempty"`
	Agent    bool   `json:"agent,omitempty"`

	Name      string          `json:"-"`
	Url       *url.URL        `json:"-"`
	Transport *http.Transport `json:"-"`
}

type SocketBackend struct {
	Upstream string    `json:"upstream,omitempty"`
	Timeout  *Duration `json:"timeout,omitempty"`
	Agent    bool      `json:"agent,omitempty"`

	Url *url.URL `json:"-"`
}

type Permission struct {
	Name      string     `json:"name"`              // Name is an identifier
	WebHook   string     `json:"webhook,omitempty"` // name of webhook provider (e.g. github)
	Locations []Location `json:"locations"`

	router *mux.Router
}

type RPCPermission struct {
	Name  string   `json:"name"`
	Allow []string `json:"allow"`
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

type Session struct {
	Type    string   `json:"type"` // secure_cookie or memcached
	KeyFile string   `json:"key_file,omitempty"`
	Servers []string `json:"servers,omitempty"`

	HashKey  []byte `json:"-"`
	BlockKey []byte `json:"-"`
}

type Dashboard struct {
	Bind         string    `json:"bind,omitempty"`
	RPCServer    string    `json:"rpc_server,omitempty"`
	TokenFile    string    `json:"token_file,omitempty"`
	Template     *Template `json:"template,omitempty"`
	PublicKeyUrl string    `json:"publickey_url,omitempty"`

	InternalToken string `json:"-"`
}

type Template struct {
	Loader string `json:"loader"` // shotgun or embed
	Dir    string `json:"dir"`
}

type Duration struct {
	time.Duration
}

func (d *Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	v := ""
	err := json.Unmarshal(b, &v)
	if err != nil {
		return err
	}

	y, err := time.ParseDuration(v)
	if err != nil {
		return err
	}
	d.Duration = y
	return nil
}

func (d *Dashboard) Load(dir string) error {
	return d.Template.inflate(dir)
}

func (t *Template) inflate(dir string) error {
	if t.Dir != "" && t.Loader == config.TemplateLoaderShotgun {
		t.Dir = filepath.Join(dir, t.Dir)
	}
	return nil
}

func (idp *IdentityProvider) Load(dir string) error {
	if idp.ClientSecretFile != "" {
		b, err := os.ReadFile(absPath(idp.ClientSecretFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		b = bytes.TrimRight(b, "\n")
		idp.ClientSecret = string(b)
	}

	return nil
}

func (ca *CertificateAuthority) Load(dir string) error {
	if ca.Local != nil {
		if ca.Local.CertFile != "" {
			b, err := os.ReadFile(absPath(ca.Local.CertFile, dir))
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			block, _ := pem.Decode(b)
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			ca.Certificate = cert

			ca.CertPool, err = x509.SystemCertPool()
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			ca.CertPool.AddCert(cert)
		}

		if ca.Local.KeyFile != "" {
			b, err := os.ReadFile(absPath(ca.Local.KeyFile, dir))
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			block, _ := pem.Decode(b)
			switch block.Type {
			case "EC PRIVATE KEY":
				privateKey, err := x509.ParseECPrivateKey(block.Bytes)
				if err != nil {
					return xerrors.Errorf(": %v", err)
				}
				ca.Local.PrivateKey = privateKey
			case "RSA PRIVATE KEY":
				privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					return xerrors.Errorf(": %v", err)
				}
				ca.Local.PrivateKey = privateKey
			case "PRIVATE KEY":
				privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					return xerrors.Errorf(": %v", err)
				}
				ca.Local.PrivateKey = privateKey
			}
		}

		ca.Local.Subject = pkix.Name{
			Organization:       []string{ca.Local.Organization},
			OrganizationalUnit: []string{ca.Local.OrganizationUnit},
			Country:            []string{ca.Local.Country},
			CommonName:         "Heimdallr CA",
		}
	}
	if ca.Vault != nil {
		if v, err := filepath.Abs(dir); err != nil {
			return xerrors.Errorf(": %w", err)
		} else {
			ca.Vault.Dir = v
		}

		if ca.Vault.Addr != "" {
			c, err := vault.NewClient(ca.Vault.Addr, ca.Vault.Token, ca.Vault.Role)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			caCert, err := c.GetCACertificate(context.TODO())
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			certPool, err := c.GetCertPool(context.TODO())
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}

			ca.CertPool = certPool
			ca.Certificate = caCert
		}
	}

	return nil
}

func (s *Session) Load(dir string) error {
	switch s.Type {
	case config.SessionTypeSecureCookie:
		b, err := os.ReadFile(absPath(s.KeyFile, dir))
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

func (p *Permission) Match(req *http.Request) bool {
	match := &mux.RouteMatch{}
	if p.router.Match(req, match) {
		return true
	}

	return false
}

func (g *AccessProxy) GetBackendByHostname(hostname string) (*Backend, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	v, ok := g.hostnameToBackend[hostname]
	return v, ok
}

// GetBackendByHost is finding Backend by Host header
func (g *AccessProxy) GetBackendByHost(host string) (*Backend, bool) {
	h := host
	if strings.Contains(host, ":") {
		s := strings.SplitN(host, ":", 2)
		h = s[0]
	}

	return g.GetBackendByHostname(h)
}

func (g *AccessProxy) GetBackend(name string) (*Backend, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.getBackend(name)
}

func (g *AccessProxy) getBackend(name string) (*Backend, bool) {
	if strings.Contains(name, "/") {
		s := strings.Split(name, "/")
		name = s[0]
	}
	v, ok := g.nameToBackend[name]
	return v, ok
}

func (g *AccessProxy) GetBackendsByRole(role *Role) ([]*Backend, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make([]*Backend, 0)
	for _, v := range role.Bindings {
		if v.Backend == "" {
			continue
		}

		b, ok := g.getBackend(v.Backend)
		if !ok {
			continue
		}
		result = append(result, b)
	}

	return result, nil
}

func (g *AccessProxy) GetAllBackends() []*Backend {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.Backends
}

func (g *AccessProxy) Load(dir string) error {
	if g.HTTP.Certificate != nil {
		if err := g.HTTP.Certificate.Load(dir); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if g.Credential != nil {
		if err := g.Credential.Load(dir); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	backends := make([]*Backend, 0)
	if g.ProxyFile != "" {
		g.ProxyFile = absPath(g.ProxyFile, dir)

		b, err := os.ReadFile(g.ProxyFile)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if err := yaml.Unmarshal(b, &backends); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	g.AuthEndpoint = fmt.Sprintf("https://%s/auth", g.HTTP.ServerName)
	g.TokenEndpoint = fmt.Sprintf("https://%s/token", g.HTTP.ServerName)
	g.ServerNameHost = g.HTTP.ServerName
	if strings.Contains(g.HTTP.ServerName, ":") {
		s := strings.Split(g.HTTP.ServerName, ":")
		g.ServerNameHost = s[0]
	}

	if g.HTTP.Session != nil {
		if err := g.HTTP.Session.Load(dir); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	return g.Setup(backends)
}

func (g *AccessProxy) Setup(backends []*Backend) error {
	proxyHostName := ""
	notWellKnownPort := ""
	if g.HTTP != nil {
		proxyHostName = g.HTTP.ServerName
		if strings.Contains(proxyHostName, ":") {
			s := strings.Split(proxyHostName, ":")
			notWellKnownPort = s[1]
		}
	}

	hostnameToBackend := make(map[string]*Backend)
	nameToBackend := make(map[string]*Backend)
	for _, v := range backends {
		if err := v.inflate(); err != nil {
			return err
		}
		if v.FQDN == "" {
			v.FQDN = v.Name + "." + g.ServerNameHost
			v.Host = v.Name + "." + proxyHostName
		} else {
			if notWellKnownPort != "" {
				v.Host = v.FQDN + ":" + notWellKnownPort
			}
		}
		hostnameToBackend[v.FQDN] = v
		nameToBackend[v.Name] = v
	}

	g.mu.Lock()
	g.Backends = backends
	g.hostnameToBackend = hostnameToBackend
	g.nameToBackend = nameToBackend
	g.mu.Unlock()
	return nil
}

func (c *Certificate) Load(dir string) error {
	if c.CertFile != "" && c.KeyFile != "" {
		c.CertFile = absPath(c.CertFile, dir)
		c.KeyFile = absPath(c.KeyFile, dir)

		c.ReloadCertificate()
		if _, err := c.GetCertificate(nil); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	return nil
}

func (c *Certificate) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.certificate == nil {
		return nil, xerrors.New("config: certificate not loaded yet")
	}

	return c.certificate, nil
}

func (c *Certificate) ReloadCertificate() error {
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	c.mu.Lock()
	c.certificate = &cert
	c.mu.Unlock()

	return nil
}

func (g *AccessProxy) ReloadConfig() error {
	backends := make([]*Backend, 0)
	b, err := os.ReadFile(g.ProxyFile)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := yaml.Unmarshal(b, &backends); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := g.Setup(backends); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (c *Credential) Load(dir string) error {
	if c.GithubWebHookSecretFile != "" {
		b, err := os.ReadFile(absPath(c.GithubWebHookSecretFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		c.GithubWebhookSecret = b
	}
	if c.InternalTokenFile != "" {
		b, err := os.ReadFile(absPath(c.InternalTokenFile, dir))
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		c.InternalToken = string(b)
	}
	if c.SigningPrivateKeyFile != "" {
		privateKey, err := readPrivateKey(absPath(c.SigningPrivateKeyFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		c.SigningPrivateKey = privateKey
		c.SigningPublicKey = privateKey.PublicKey
	}

	return nil
}

func (a *AuthorizationEngine) Load(dir string) error {
	roles := make([]*Role, 0)
	rpcPermissions := make([]*RPCPermission, 0)
	if a.RoleFile != "" {
		a.RoleFile = absPath(a.RoleFile, dir)

		b, err := os.ReadFile(a.RoleFile)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if err := yaml.Unmarshal(b, &roles); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}
	if a.RPCPermissionFile != "" {
		a.RPCPermissionFile = absPath(a.RPCPermissionFile, dir)

		b, err := os.ReadFile(a.RPCPermissionFile)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if err := yaml.Unmarshal(b, &rpcPermissions); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	return a.Setup(roles, rpcPermissions)
}

func (a *AuthorizationEngine) GetAllRoles() []*Role {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return a.Roles
}

func (a *AuthorizationEngine) GetRole(name string) (*Role, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if v, ok := a.roleNameToRole[name]; ok {
		return v, nil
	}

	return &Role{}, config.ErrRoleNotFound
}

func (a *AuthorizationEngine) GetRPCPermission(name string) (*RPCPermission, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if v, ok := a.nameToRpcPermission[name]; ok {
		return v, true
	}

	return nil, false
}

func (a *AuthorizationEngine) ReloadConfig() error {
	roles := make([]*Role, 0)
	b, err := os.ReadFile(a.RoleFile)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := yaml.Unmarshal(b, &roles); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	rpcPermissions := make([]*RPCPermission, 0)
	b, err = os.ReadFile(a.RPCPermissionFile)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := yaml.Unmarshal(b, &rpcPermissions); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := a.Setup(roles, rpcPermissions); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (a *AuthorizationEngine) Setup(roles []*Role, rpcPermissions []*RPCPermission) error {
	roles = append(roles, SystemRole)
	rpcPermissions = append(rpcPermissions, SystemRPCPermission)

	nameToRpcPermission := make(map[string]*RPCPermission)
	for _, v := range rpcPermissions {
		nameToRpcPermission[v.Name] = v
	}
	roleNameToRole := make(map[string]*Role)
	for _, v := range roles {
		m := rpc.NewMethodMatcher()
		for _, v := range v.Bindings {
			if v.RPC != "" {
				p := nameToRpcPermission[v.RPC]
				for _, method := range p.Allow {
					if err := m.Add(method); err != nil {
						return err
					}
				}
				continue
			}
		}
		v.RPCMethodMatcher = m
		roleNameToRole[v.Name] = v
	}

	a.mu.Lock()
	a.Roles = roles
	a.RPCPermissions = rpcPermissions
	a.roleNameToRole = roleNameToRole
	a.nameToRpcPermission = nameToRpcPermission
	a.mu.Unlock()

	return nil
}

func (d *Datastore) Load(dir string) error {
	if d.DatastoreEtcd.RawUrl != "" {
		if strings.HasPrefix(d.DatastoreEtcd.RawUrl, "mysql://") {
			cfg, err := mysql.ParseDSN(d.DatastoreEtcd.RawUrl[8:])
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			cfg.ParseTime = true
			cfg.Loc = time.Local
			d.DSN = cfg
		} else {
			u, err := url.Parse(d.DatastoreEtcd.RawUrl)
			if err != nil {
				return err
			}
			d.Url = u

			if u.Host == "embed" {
				d.Embed = true
			}
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

	if d.CACertFile != "" {
		b, err := os.ReadFile(absPath(d.CACertFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		block, _ := pem.Decode(b)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		d.CertPool = x509.NewCertPool()
		d.CertPool.AddCert(cert)
	}
	if d.CertFile != "" && d.KeyFile != "" {
		b, err := os.ReadFile(absPath(d.CertFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		k, err := os.ReadFile(absPath(d.KeyFile, dir))
		c, err := tls.X509KeyPair(b, k)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		d.Certificate = c
	}

	if d.Url == nil {
		return nil
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
				if err := os.MkdirAll(filepath.Join(d.DataDir), 0700); err != nil {
					return xerrors.Errorf(": %v", err)
				}
				err = os.WriteFile(filepath.Join(d.DataDir, EmbedEtcdUrlFilename), []byte(u.String()), 0600)
				if err != nil {
					return xerrors.Errorf(": %v", err)
				}
				d.EtcdUrl = u
			} else {
				b, err := os.ReadFile(filepath.Join(d.DataDir, EmbedEtcdUrlFilename))
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
	case "etcds":
		if d.CertPool == nil {
			return xerrors.New("ca_cert_file, cert_file and key_file are a mandatory value")
		}

		u := new(url.URL)
		*u = *d.Url
		u.Scheme = "https"
		d.EtcdUrl = u
	}

	return nil
}

func (d *Datastore) GetEtcdClient(loggerConf *Logger) (*clientv3.Client, error) {
	if d.etcdClient != nil {
		return d.etcdClient, nil
	}

	encoder := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	var tlsConfig *tls.Config
	if d.CertPool != nil {
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{d.Certificate},
			RootCAs:      d.CertPool,
		}
	}
	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{d.EtcdUrl.String()},
		DialTimeout: 1 * time.Second,
		LogConfig:   loggerConf.ZapConfig(encoder),
		TLS:         tlsConfig,
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

func (d *Datastore) GetMySQLConn() (*sql.DB, error) {
	conn, err := sql.Open("mysql", d.DSN.FormatDSN())
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	return conn, nil
}

func (b *Backend) inflate() error {
	for _, p := range b.Permissions {
		p.inflate()
	}

	selector := NewHTTPBackendSelector()
	if len(b.HTTP) > 0 {
		agent := false
		for _, v := range b.HTTP {
			if v.Path[0] != '/' {
				return xerrors.Errorf("Path must start with a slash: %s", b.Name)
			}

			selector.Add(v)

			if v.Agent {
				agent = true
			}
			v.Name = b.Name + v.Path

			upstream := v.Upstream
			if upstream == "" {
				upstream = "http://:0"
			}
			u, err := url.Parse(upstream)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			v.Url = u

			var tlsConfig *tls.Config
			if v.Insecure {
				tlsConfig = &tls.Config{
					InsecureSkipVerify: true,
				}
			}
			v.Transport = &http.Transport{
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				MaxConnsPerHost:       16,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				TLSClientConfig:       tlsConfig,
			}
		}
		b.Agent = agent
	}
	b.BackendSelector = selector

	if b.Socket != nil {
		u, err := url.Parse(b.Socket.Upstream)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		b.Socket.Url = u
		if b.Socket.Agent {
			b.Agent = true
		}
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

func (l *Logger) ZapConfig(encoder zapcore.EncoderConfig) *zap.Config {
	level := zap.InfoLevel
	switch l.Level {
	case "debug":
		level = zap.DebugLevel
	case "warn":
		level = zap.WarnLevel
	case "error":
		level = zap.ErrorLevel
	case "panic":
		level = zap.PanicLevel
	case "fatal":
		level = zap.FatalLevel
	}
	encoding := "json"
	if l.Encoding != "" {
		encoding = l.Encoding
	}

	return &zap.Config{
		Level:            zap.NewAtomicLevelAt(level),
		Development:      false,
		Sampling:         nil, // disable sampling
		Encoding:         encoding,
		EncoderConfig:    encoder,
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
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
	b, err := os.ReadFile(path)
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
