package config

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

	"go.f110.dev/heimdallr/pkg/k8s"
	"go.f110.dev/heimdallr/pkg/rpc"
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
	RPCServer        *RPCServer        `json:"rpc_server,omitempty"`
	IdentityProvider *IdentityProvider `json:"identity_provider,omitempty"`
	Datastore        *Datastore        `json:"datastore,omitempty"`
	Logger           *Logger           `json:"logger,omitempty"`
	FrontendProxy    *FrontendProxy    `json:"frontend_proxy,omitempty"`
	Dashboard        *Dashboard        `json:"dashboard,omitempty"`
}

type General struct {
	Enable                bool                  `json:"enable"`
	EnableHttp            bool                  `json:"enable_http,omitempty"`
	Debug                 bool                  `json:"debug,omitempty"`
	Bind                  string                `json:"bind,omitempty"`
	BindHttp              string                `json:"bind_http,omitempty"`
	BindInternalApi       string                `json:"bind_internal_api,omitempty"`
	ServerName            string                `json:"server_name,omitempty"`
	CertFile              string                `json:"cert_file,omitempty"`
	KeyFile               string                `json:"key_file,omitempty"`
	RoleFile              string                `json:"role_file,omitempty"`
	ProxyFile             string                `json:"proxy_file,omitempty"`
	RpcPermissionFile     string                `json:"rpc_permission_file,omitempty"`
	RpcTarget             string                `json:"rpc_target,omitempty"`
	CertificateAuthority  *CertificateAuthority `json:"certificate_authority,omitempty"`
	RootUsers             []string              `json:"root_users,omitempty"`
	SigningPrivateKeyFile string                `json:"signing_private_key_file,omitempty"`
	InternalTokenFile     string                `json:"internal_token_file,omitempty"`

	mu                  sync.RWMutex              `json:"-"`
	Roles               []*Role                   `json:"-"`
	Backends            []*Backend                `json:"-"`
	RpcPermissions      []*RpcPermission          `json:"-"`
	hostnameToBackend   map[string]*Backend       `json:"-"`
	nameToBackend       map[string]*Backend       `json:"-"`
	roleNameToRole      map[string]*Role          `json:"-"`
	nameToRpcPermission map[string]*RpcPermission `json:"-"`
	watcher             *k8s.VolumeWatcher        `json:"-"`

	SigningPrivateKey *ecdsa.PrivateKey `json:"-"`
	SigningPublicKey  ecdsa.PublicKey   `json:"-"`
	InternalToken     string            `json:"-"`

	AuthEndpoint   string `json:"-"`
	TokenEndpoint  string `json:"-"`
	ServerNameHost string `json:"-"`

	certMu      sync.RWMutex
	certificate *tls.Certificate `json:"-"`
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

type RPCServer struct {
	Bind        string `json:"bind,omitempty"`
	MetricsBind string `json:"metrics_bind,omitempty"`
	Enable      bool   `json:"enable,omitempty"`
}

type IdentityProvider struct {
	Provider         string   `json:"provider"` // "google", "okta", "azure" or "custom"
	Issuer           string   `json:"issuer"`   // for "custom"
	ClientId         string   `json:"client_id"`
	ClientSecretFile string   `json:"client_secret_file"`
	ExtraScopes      []string `json:"extra_scopes"`
	Domain           string   `json:"domain,omitempty"` // for Okta and AzureAD
	RedirectUrl      string   `json:"redirect_url"`

	ClientSecret string `json:"-"`
}

type Datastore struct {
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

	DSN *mysql.Config `json:"-"`

	etcdClient *clientv3.Client `json:"-"`
}

type Logger struct {
	Level    string `json:"level"`
	Encoding string `json:"encoding"` // json or console
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
	Rpc        string `json:"rpc,omitempty"`
	Backend    string `json:"backend,omitempty"`    // Backend is Backend.Name
	Permission string `json:"permission,omitempty"` // Permission is Permission.Name

	FQDN string `json:"-"`
}

type Backend struct {
	Name          string        `json:"name"` // Name is an identifier
	FQDN          string        `json:"fqdn,omitempty"`
	Upstream      string        `json:"upstream"`
	Permissions   []*Permission `json:"permissions"`
	WebHook       string        `json:"webhook,omitempty"` // name of webhook provider (e.g. github)
	WebHookPath   []string      `json:"webhook_path,omitempty"`
	Agent         bool          `json:"agent,omitempty"`
	AllowRootUser bool          `json:"allow_root_user,omitempty"`
	DisableAuthn  bool          `json:"disable_authn,omitempty"`
	Insecure      bool          `json:"insecure,omitempty"`
	AllowHttp     bool          `json:"allow_http,omitempty"`
	Socket        bool          `json:"socket,omitempty"`
	SocketTimeout *Duration     `json:"socket_timeout,omitempty"`
	// MaxSessionDuration is a maximum duration before session expire for specify backend.
	// When MaxSessionDuration is not empty, OIDC authentication is required even if the user submits a client certificate.
	MaxSessionDuration *Duration `json:"max_session_duration,omitempty"`

	Url           *url.URL        `json:"-"`
	WebHookRouter *mux.Router     `json:"-"`
	Transport     *http.Transport `json:"-"`
}

type Permission struct {
	Name      string     `json:"name"` // Name is an identifier
	Locations []Location `json:"locations"`

	router *mux.Router `json:"-"`
}

type RpcPermission struct {
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

type FrontendProxy struct {
	GithubWebHookSecretFile string   `json:"github_webhook_secret_file"`
	ExpectCT                bool     `json:"expect_ct"`
	Session                 *Session `json:"session,omitempty"`

	Certificate         tls.Certificate `json:"-"`
	GithubWebhookSecret []byte          `json:"-"`
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
	if ca.CertFile != "" {
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
		ca.CertPool, err = x509.SystemCertPool()
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		ca.CertPool.AddCert(cert)
	}

	if ca.KeyFile != "" {
		b, err := ioutil.ReadFile(absPath(ca.KeyFile, dir))
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
		CommonName:         "Heimdallr CA",
	}

	return nil
}

func (f *FrontendProxy) Inflate(dir string) error {
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

	return g.getBackend(name)
}

func (g *General) getBackend(name string) (*Backend, bool) {
	v, ok := g.nameToBackend[name]
	return v, ok
}

func (g *General) GetBackendsByRole(roleName string) ([]*Backend, error) {
	role, err := g.GetRole(roleName)
	if err != nil {
		return nil, err
	}

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

func (g *General) GetAllBackends() []*Backend {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.Backends
}

func (g *General) GetAllRoles() []*Role {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.Roles
}

func (g *General) GetRole(name string) (*Role, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if v, ok := g.roleNameToRole[name]; ok {
		return v, nil
	}

	return &Role{}, ErrRoleNotFound
}

func (g *General) GetRpcPermission(name string) (*RpcPermission, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if v, ok := g.nameToRpcPermission[name]; ok {
		return v, true
	}

	return nil, false
}

func (g *General) Inflate(dir string) error {
	if g.CertFile != "" && g.KeyFile != "" {
		g.CertFile = absPath(g.CertFile, dir)
		g.KeyFile = absPath(g.KeyFile, dir)

		g.reloadCertificate()
		if _, err := g.GetCertificate(nil); err != nil {
			return xerrors.Errorf(": %v", err)
		}

		if k8s.CanWatchVolume(absPath(g.RoleFile, dir)) {
			mountPath, err := k8s.FindMountPath(g.CertFile)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			fmt.Fprintf(os.Stderr, "watch volume: %s\n", mountPath)
			_, err = k8s.NewVolumeWatcher(mountPath, g.reloadCertificate)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
		}
	}

	roles := make([]*Role, 0)
	backends := make([]*Backend, 0)
	rpcPermissions := make([]*RpcPermission, 0)
	if g.RoleFile != "" {
		g.RoleFile = absPath(g.RoleFile, dir)

		b, err := ioutil.ReadFile(g.RoleFile)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if err := yaml.Unmarshal(b, &roles); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}
	if g.ProxyFile != "" {
		g.ProxyFile = absPath(g.ProxyFile, dir)

		b, err := ioutil.ReadFile(g.ProxyFile)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if err := yaml.Unmarshal(b, &backends); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}
	if g.RpcPermissionFile != "" {
		g.RpcPermissionFile = absPath(g.RpcPermissionFile, dir)

		b, err := ioutil.ReadFile(g.RpcPermissionFile)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if err := yaml.Unmarshal(b, &rpcPermissions); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}
	if g.RoleFile != "" && g.ProxyFile != "" && g.RpcPermissionFile != "" {
		if k8s.CanWatchVolume(g.RoleFile) {
			mountPath, err := k8s.FindMountPath(g.RoleFile)
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

	if g.CertificateAuthority != nil {
		if err := g.CertificateAuthority.inflate(dir); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	if g.SigningPrivateKeyFile != "" {
		privateKey, err := readPrivateKey(absPath(g.SigningPrivateKeyFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		g.SigningPrivateKey = privateKey
		g.SigningPublicKey = privateKey.PublicKey
	}

	if g.InternalTokenFile != "" {
		b, err := ioutil.ReadFile(absPath(g.InternalTokenFile, dir))
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		g.InternalToken = string(b)
	}

	g.AuthEndpoint = fmt.Sprintf("https://%s/auth", g.ServerName)
	g.TokenEndpoint = fmt.Sprintf("https://%s/token", g.ServerName)
	g.ServerNameHost = g.ServerName
	if strings.Contains(g.ServerName, ":") {
		s := strings.Split(g.ServerName, ":")
		g.ServerNameHost = s[0]
	}

	return g.Load(backends, roles, rpcPermissions)
}

func (g *General) Load(backends []*Backend, roles []*Role, rpcPermissions []*RpcPermission) error {
	rpcPermissions = append(rpcPermissions, &RpcPermission{
		Name: "system:proxy",
		Allow: []string{
			"proxy.rpc.certificateauthority.watchrevokedcert",
			"proxy.rpc.certificateauthority.newservercert",
			"proxy.rpc.cluster.defragmentdatastore",
			"proxy.rpc.authority.signrequest",
			"proxy.rpc.authority.getpublickey",
		},
	})
	roles = append(roles, &Role{
		Name: "system:proxy",
		Bindings: []*Binding{
			{Rpc: "system:proxy"},
		},
		System: true,
	})

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

	nameToRpcPermission := make(map[string]*RpcPermission)
	for _, v := range rpcPermissions {
		nameToRpcPermission[v.Name] = v
	}

	roleNameToRole := make(map[string]*Role)
	for _, v := range roles {
		m := rpc.NewMethodMatcher()
		for _, v := range v.Bindings {
			if v.Rpc != "" {
				p := nameToRpcPermission[v.Rpc]
				for _, method := range p.Allow {
					if err := m.Add(method); err != nil {
						return err
					}
				}
				continue
			}

			b, ok := nameToBackend[v.Backend]
			if !ok {
				continue
			}
			v.FQDN = b.FQDN
		}
		v.RPCMethodMatcher = m
		roleNameToRole[v.Name] = v
	}

	g.mu.Lock()
	g.Backends = backends
	g.Roles = roles
	g.RpcPermissions = rpcPermissions
	g.hostnameToBackend = hostnameToBackend
	g.nameToBackend = nameToBackend
	g.roleNameToRole = roleNameToRole
	g.nameToRpcPermission = nameToRpcPermission
	g.mu.Unlock()
	return nil
}

func (g *General) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	g.certMu.RLock()
	defer g.certMu.RUnlock()

	if g.certificate == nil {
		return nil, xerrors.New("config: certificate not loaded yet")
	}

	return g.certificate, nil
}

func (g *General) reloadConfig() {
	roles := make([]*Role, 0)
	b, err := ioutil.ReadFile(g.RoleFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed load config file: %+v\n", err)
		return
	}
	if err := yaml.Unmarshal(b, &roles); err != nil {
		fmt.Fprintf(os.Stderr, "Failed load config file: %+v\n", err)
		return
	}

	backends := make([]*Backend, 0)
	b, err = ioutil.ReadFile(g.ProxyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed load config file: %+v\n", err)
		return
	}
	if err := yaml.Unmarshal(b, &backends); err != nil {
		fmt.Fprintf(os.Stderr, "Failed load config file: %+v\n", err)
		return
	}

	rpcPermissions := make([]*RpcPermission, 0)
	b, err = ioutil.ReadFile(g.RpcPermissionFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed load config file: %+v\n", err)
		return
	}
	if err := yaml.Unmarshal(b, &rpcPermissions); err != nil {
		fmt.Fprintf(os.Stderr, "Failed load config file: %+v\n", err)
		return
	}

	if err := g.Load(backends, roles, rpcPermissions); err != nil {
		fmt.Fprintf(os.Stderr, "Failed load config file: %+v\n", err)
	}
	fmt.Fprintf(os.Stderr, "%s\tReload role and proxy config file\n", time.Now().Format(time.RFC3339))
}

func (g *General) reloadCertificate() {
	cert, err := tls.LoadX509KeyPair(g.CertFile, g.KeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed load server certificate: %v\n", err)
		return
	}

	g.certMu.Lock()
	g.certificate = &cert
	g.certMu.Unlock()
}

func (d *Datastore) Inflate(dir string) error {
	if d.RawUrl != "" {
		if strings.HasPrefix(d.RawUrl, "mysql://") {
			cfg, err := mysql.ParseDSN(d.RawUrl[8:])
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			cfg.ParseTime = true
			cfg.Loc = time.Local
			d.DSN = cfg
		} else {
			u, err := url.Parse(d.RawUrl)
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
	if b.Insecure {
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
