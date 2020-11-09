package configv2

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
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

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"go.etcd.io/etcd/v3/clientv3"
	"go.etcd.io/etcd/v3/clientv3/namespace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"

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

	mu       sync.RWMutex `json:"-"`
	Backends []*Backend   `json:"-"`

	hostnameToBackend map[string]*Backend `json:"-"`
	nameToBackend     map[string]*Backend `json:"-"`
	watcher           *k8s.VolumeWatcher  `json:"-"`

	AuthEndpoint   string `json:"-"`
	TokenEndpoint  string `json:"-"`
	ServerNameHost string `json:"-"`
}

type AuthorizationEngine struct {
	RoleFile          string   `json:"role_file,omitempty"`
	RPCPermissionFile string   `json:"rpc_permission_file,omitempty"`
	RootUsers         []string `json:"root_users,omitempty"`

	mu                  sync.RWMutex              `json:"-"`
	Roles               []*Role                   `json:"-"`
	RPCPermissions      []*RPCPermission          `json:"-"`
	roleNameToRole      map[string]*Role          `json:"-"`
	nameToRpcPermission map[string]*RPCPermission `json:"-"`
	watcher             *k8s.VolumeWatcher        `json:"-"`
}

type CertificateAuthority struct {
	Local *CertificateAuthorityLocal `json:"local"`
}

type CertificateAuthorityLocal struct {
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

	etcdClient *clientv3.Client `json:"-"`
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
	certificate *tls.Certificate `json:"-"`
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
	Name             string `json:"name"` // Name is an identifier
	FQDN             string `json:"fqdn,omitempty"`
	Upstream         string `json:"upstream"`
	InsecureUpstream bool   `json:"insecure_upstream,omitempty"`
	Agent            bool   `json:"agent,omitempty"`

	Permissions   []*Permission `json:"permissions"`
	AllowRootUser bool          `json:"allow_root_user,omitempty"`
	DisableAuthn  bool          `json:"disable_authn,omitempty"`
	// MaxSessionDuration is a maximum duration before session expire for specify backend.
	// When MaxSessionDuration is not empty, OIDC authentication is required even if the user submits a client certificate.
	MaxSessionDuration *Duration `json:"max_session_duration,omitempty"`

	WebHook       string    `json:"webhook,omitempty"` // name of webhook provider (e.g. github)
	WebHookPath   []string  `json:"webhook_path,omitempty"`
	AllowHttp     bool      `json:"allow_http,omitempty"`
	Socket        bool      `json:"socket,omitempty"`
	SocketTimeout *Duration `json:"socket_timeout,omitempty"`

	Url           *url.URL        `json:"-"`
	WebHookRouter *mux.Router     `json:"-"`
	Transport     *http.Transport `json:"-"`
}

type Permission struct {
	Name      string     `json:"name"` // Name is an identifier
	Locations []Location `json:"locations"`

	router *mux.Router `json:"-"`
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
	Bind      string    `json:"bind,omitempty"`
	RPCServer string    `json:"rpc_server,omitempty"`
	TokenFile string    `json:"token_file,omitempty"`
	Template  *Template `json:"template,omitempty"`

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
		b, err := ioutil.ReadFile(absPath(idp.ClientSecretFile, dir))
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
			b, err := ioutil.ReadFile(absPath(ca.Local.CertFile, dir))
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			block, _ := pem.Decode(b)
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			ca.Local.Certificate = cert
			ca.Local.CertPool, err = x509.SystemCertPool()
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			ca.Local.CertPool.AddCert(cert)
		}

		if ca.Local.KeyFile != "" {
			b, err := ioutil.ReadFile(absPath(ca.Local.KeyFile, dir))
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

	return nil
}

func (s *Session) Load(dir string) error {
	switch s.Type {
	case config.SessionTypeSecureCookie:
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

		b, err := ioutil.ReadFile(g.ProxyFile)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if err := yaml.Unmarshal(b, &backends); err != nil {
			return xerrors.Errorf(": %v", err)
		}

		if k8s.CanWatchVolume(g.ProxyFile) {
			mountPath, err := k8s.FindMountPath(g.ProxyFile)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			fmt.Fprintf(os.Stderr, "watch volume: %s\n", mountPath)
			w, err := k8s.NewVolumeWatcher(mountPath, g.reloadConfig)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			g.watcher = w
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
	hostnameToBackend := make(map[string]*Backend)
	nameToBackend := make(map[string]*Backend)
	for _, v := range backends {
		if err := v.inflate(); err != nil {
			return err
		}
		if v.FQDN == "" {
			v.FQDN = v.Name + "." + g.ServerNameHost
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

		c.reloadCertificate()
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

func (c *Certificate) reloadCertificate() {
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed load server certificate: %v\n", err)
		return
	}

	c.mu.Lock()
	c.certificate = &cert
	c.mu.Unlock()
}

func (g *AccessProxy) reloadConfig() {
	backends := make([]*Backend, 0)
	b, err := ioutil.ReadFile(g.ProxyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed load config file: %+v\n", err)
		return
	}
	if err := yaml.Unmarshal(b, &backends); err != nil {
		fmt.Fprintf(os.Stderr, "Failed load config file: %+v\n", err)
		return
	}

	if err := g.Setup(backends); err != nil {
		fmt.Fprintf(os.Stderr, "Failed load config file: %+v\n", err)
	}
	fmt.Fprintf(os.Stderr, "%s\tReload proxy config file\n", time.Now().Format(time.RFC3339))
}

func (c *Credential) Load(dir string) error {
	if c.GithubWebHookSecretFile != "" {
		b, err := ioutil.ReadFile(absPath(c.GithubWebHookSecretFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		c.GithubWebhookSecret = b
	}
	if c.InternalTokenFile != "" {
		b, err := ioutil.ReadFile(absPath(c.InternalTokenFile, dir))
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

		b, err := ioutil.ReadFile(a.RoleFile)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if err := yaml.Unmarshal(b, &roles); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}
	if a.RPCPermissionFile != "" {
		a.RPCPermissionFile = absPath(a.RPCPermissionFile, dir)

		b, err := ioutil.ReadFile(a.RPCPermissionFile)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if err := yaml.Unmarshal(b, &rpcPermissions); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}
	if k8s.CanWatchVolume(a.RoleFile) {
		mountPath, err := k8s.FindMountPath(a.RoleFile)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		fmt.Fprintf(os.Stderr, "watch volume: %s\n", mountPath)
		w, err := k8s.NewVolumeWatcher(mountPath, a.reloadConfig)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		a.watcher = w
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

func (a *AuthorizationEngine) reloadConfig() {
	roles := make([]*Role, 0)
	b, err := ioutil.ReadFile(a.RoleFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed load config file: %+v\n", err)
		return
	}
	if err := yaml.Unmarshal(b, &roles); err != nil {
		fmt.Fprintf(os.Stderr, "Failed load config file: %+v\n", err)
		return
	}

	rpcPermissions := make([]*RPCPermission, 0)
	b, err = ioutil.ReadFile(a.RPCPermissionFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed load config file: %+v\n", err)
		return
	}
	if err := yaml.Unmarshal(b, &rpcPermissions); err != nil {
		fmt.Fprintf(os.Stderr, "Failed load config file: %+v\n", err)
		return
	}

	if err := a.Setup(roles, rpcPermissions); err != nil {
		fmt.Fprintf(os.Stderr, "Failed load role and rpc permission config file: %+v\n", err)
	}

	fmt.Fprintf(os.Stderr, "%s\tReload role and rpc permission successfully\n", time.Now().Format(time.RFC3339))
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
		b, err := ioutil.ReadFile(absPath(d.CACertFile, dir))
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
		b, err := ioutil.ReadFile(absPath(d.CertFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		k, err := ioutil.ReadFile(absPath(d.KeyFile, dir))
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
	u, err := url.Parse(b.Upstream)
	if err != nil {
		return xerrors.Errorf("%s: %v", b.Name, err)
	}
	b.Url = u

	if b.Agent && b.Upstream == "" {
		b.Url = &url.URL{Scheme: "http", Host: "via-agent"}
	}

	if u.Scheme == "tcp" {
		b.Socket = true
	}

	if len(b.WebHookPath) > 0 {
		m := mux.NewRouter()
		for _, v := range b.WebHookPath {
			m.PathPrefix(v)
		}
		b.WebHookRouter = m
	}

	var tlsConfig *tls.Config
	if b.InsecureUpstream {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	b.Transport = &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxConnsPerHost:       16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
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
