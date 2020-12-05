package framework

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/securecookie"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/pkg/auth"
	"go.f110.dev/heimdallr/pkg/authproxy"
	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/netutil"
	"go.f110.dev/heimdallr/pkg/rpc"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
	"go.f110.dev/heimdallr/pkg/session"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var (
	binaryPath *string
)

func init() {
	binaryPath = flag.String("e2e.binary", "", "")
}

type Proxy struct {
	Domain     string
	DomainHost string
	CA         *x509.Certificate

	sessionStore *session.SecureCookieStore

	t              *testing.T
	running        bool
	dir            string
	proxyPort      int
	internalPort   int
	rpcPort        int
	dashboardPort  int
	internalToken  string
	caCert         *x509.Certificate
	caPrivateKey   crypto.PrivateKey
	signPrivateKey *ecdsa.PrivateKey
	backends       []*config.Backend
	roles          []*config.Role
	users          []*database.User

	configBuf                []byte
	proxyConfBuf             []byte
	roleConfBuf              []byte
	rpcPermissionConfBuf     []byte
	prevConfigBuf            []byte
	prevProxyConfBuf         []byte
	prevRoleConfBuf          []byte
	prevRpcPermissionConfBuf []byte

	identityProvider *IdentityProvider
	proxyCmd         *exec.Cmd
	err              error
}

func NewProxy(t *testing.T) (*Proxy, error) {
	dir, err := ioutil.TempDir("", "heimdallr")
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "data"), 0700); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	signReqKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	b, err := x509.MarshalECPrivateKey(signReqKey)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	if err := cert.PemEncode(filepath.Join(dir, "privatekey.pem"), "EC PRIVATE KEY", b, nil); err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	b, err = x509.MarshalPKIXPublicKey(signReqKey.Public())
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if err := cert.PemEncode(filepath.Join(dir, "publickey.pem"), "PUBLIC KEY", b, nil); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	caCert, caPrivateKey, err := cert.CreateCertificateAuthority("heimdallr proxy e2e", "test", "e2e", "jp")
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	b, err = x509.MarshalECPrivateKey(caPrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if err := cert.PemEncode(filepath.Join(dir, "ca.crt"), "CERTIFICATE", caCert.Raw, nil); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if err := cert.PemEncode(filepath.Join(dir, "ca.key"), "EC PRIVATE KEY", b, nil); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	internalToken := make([]byte, 32)
	for i := range internalToken {
		internalToken[i] = letters[mrand.Intn(len(letters))]
	}
	f, err := os.Create(filepath.Join(dir, "internal_token"))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	f.Write(internalToken)
	f.Close()
	hashKey := securecookie.GenerateRandomKey(32)
	blockKey := securecookie.GenerateRandomKey(16)
	f, err = os.Create(filepath.Join(dir, "cookie_secret"))
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	f.WriteString(hex.EncodeToString(hashKey))
	f.WriteString("\n")
	f.WriteString(hex.EncodeToString(blockKey))
	f.Close()

	sessionStore := session.NewSecureCookieStore([]byte(hex.EncodeToString(hashKey)), []byte(hex.EncodeToString(blockKey)), "e2e.f110.dev")

	if err := ioutil.WriteFile(filepath.Join(dir, "identityprovider"), []byte("identityprovider"), 0644); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	idp, err := NewIdentityProvider()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	proxyPort, err := netutil.FindUnusedPort()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	internalPort, err := netutil.FindUnusedPort()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	rpcPort, err := netutil.FindUnusedPort()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	dashboardPort, err := netutil.FindUnusedPort()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return &Proxy{
		Domain:           fmt.Sprintf("e2e.f110.dev:%d", proxyPort),
		DomainHost:       "e2e.f110.dev",
		CA:               caCert,
		sessionStore:     sessionStore,
		t:                t,
		dir:              dir,
		identityProvider: idp,
		signPrivateKey:   signReqKey,
		caCert:           caCert,
		caPrivateKey:     caPrivateKey,
		proxyPort:        proxyPort,
		internalPort:     internalPort,
		rpcPort:          rpcPort,
		dashboardPort:    dashboardPort,
		internalToken:    string(internalToken),
	}, nil
}

func (p *Proxy) URL(subdomain string, pathAnd ...string) string {
	path := ""
	if len(pathAnd) > 0 {
		path = pathAnd[0]
	}
	if path == "" {
		return fmt.Sprintf("https://%s.%s/", subdomain, p.Domain)
	} else {
		u := &url.URL{
			Scheme: "https",
			Path:   path,
		}
		if subdomain == "" {
			u.Host = p.Domain
		} else {
			u.Host = subdomain + "." + p.Domain
		}
		return u.String()
	}
}

func (p *Proxy) Backend(b *config.Backend) {
	p.backends = append(p.backends, b)
}

func (p *Proxy) Role(r *config.Role) {
	p.roles = append(p.roles, r)
}

func (p *Proxy) User(u *database.User) {
	p.users = append(p.users, u)
}

func (p *Proxy) Cleanup() error {
	if err := p.stop(); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return os.RemoveAll(p.dir)
}

func (p *Proxy) Reload() error {
	if err := p.buildConfig(); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if changed, err := p.isChangedConfig(); err != nil {
		return xerrors.Errorf(": %w", err)
	} else if !changed {
		return nil
	}

	if p.running {
		if err := p.stop(); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if err := p.start(); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := p.syncUsers(); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (p *Proxy) syncUsers() error {
	caPool, err := x509.SystemCertPool()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	caPool.AddCert(p.caCert)

	cred := credentials.NewTLS(&tls.Config{ServerName: rpc.ServerHostname, RootCAs: caPool})
	conn, err := grpc.Dial(
		fmt.Sprintf("127.0.0.1:%d", p.rpcPort),
		grpc.WithTransportCredentials(cred),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: time.Second, PermitWithoutStream: true}),
		grpc.WithStreamInterceptor(grpc_retry.StreamClientInterceptor()),
		grpc.WithUnaryInterceptor(grpc_retry.UnaryClientInterceptor()),
	)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	claim := jwt.NewWithClaims(jwt.SigningMethodES256, &auth.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        "root@e2e.f110.dev",
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(authproxy.TokenExpiration).Unix(),
		},
	})
	token, err := claim.SignedString(p.signPrivateKey)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	client := rpcclient.NewClientWithUserToken(conn).WithToken(token)
	users, err := client.ListAllUser()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	for _, user := range users {
		if user.Id == database.SystemUser.Id {
			continue
		}
		for _, r := range user.Roles {
			if err := client.DeleteUser(user.Id, r); err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}

	for _, user := range p.users {
		for _, r := range user.Roles {
			if err := client.AddUser(user.Id, r); err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}

	return nil
}

func (p *Proxy) isChangedConfig() (bool, error) {
	if p.configBuf == nil || p.proxyConfBuf == nil || p.roleConfBuf == nil || p.rpcPermissionConfBuf == nil {
		return true, nil
	}

	if !bytes.Equal(p.prevConfigBuf, p.configBuf) {
		return true, nil
	}
	if !bytes.Equal(p.prevProxyConfBuf, p.proxyConfBuf) {
		return true, nil
	}
	if !bytes.Equal(p.prevRoleConfBuf, p.roleConfBuf) {
		return true, nil
	}
	if !bytes.Equal(p.prevRpcPermissionConfBuf, p.rpcPermissionConfBuf) {
		return true, nil
	}

	return false, nil
}

func (p *Proxy) start() error {
	if err := p.setup(p.dir); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := p.startProcess(); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return p.waitForStart()
}

func (p *Proxy) startProcess() error {
	p.proxyCmd = exec.Command(*binaryPath, "-c", filepath.Join(p.dir, "config.yaml"))
	if *verbose {
		p.proxyCmd.Stdout = os.Stdout
		p.proxyCmd.Stderr = os.Stderr
	}
	err := p.proxyCmd.Start()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	p.running = true
	p.t.Logf("Start process :%d rpc :%d", p.proxyPort, p.rpcPort)

	return nil
}

func (p *Proxy) stop() error {
	var wg sync.WaitGroup
	if p.proxyCmd != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()

			p.proxyCmd.Process.Wait()
		}()

		if err := p.proxyCmd.Process.Signal(os.Interrupt); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		done <- struct{}{}
	}()

	select {
	case <-time.After(10 * time.Second):
		log.Print("stopping proxy process was timed out. We are going to send KILL signal to stop process forcibly.")
		return p.proxyCmd.Process.Signal(os.Kill)
	case <-done:
	}

	return nil
}

func (p *Proxy) waitForStart() error {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	timeout := time.After(10 * time.Second)
	for {
		select {
		case <-t.C:
			conn, err := net.Dial("tcp", fmt.Sprintf(":%d", p.proxyPort))
			if err != nil {
				continue
			}

			conn.Close()
			return nil
		case <-timeout:
			if p.running {
				_ = p.stop()
			}
			return xerrors.New("waiting for start process is timed out")
		}
	}
}

func (p *Proxy) setup(dir string) error {
	s := strings.SplitN(p.Domain, ":", 2)
	hosts := []string{s[0]}
	for _, b := range p.backends {
		if b.FQDN != "" {
			hosts = append(hosts, b.FQDN)
			continue
		}
		if b.Name != "" {
			hosts = append(hosts, fmt.Sprintf("%s.%s", b.Name, s[0]))
			continue
		}
	}
	c, privateKey, err := cert.GenerateServerCertificate(p.caCert, p.caPrivateKey, hosts)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	b, err := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := cert.PemEncode(filepath.Join(dir, "tls.key"), "EC PRIVATE KEY", b, nil); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := cert.PemEncode(filepath.Join(dir, "tls.crt"), "CERTIFICATE", c.Raw, nil); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (p *Proxy) buildConfig() error {
	p.prevConfigBuf = p.configBuf
	p.prevProxyConfBuf = p.proxyConfBuf
	p.prevRoleConfBuf = p.roleConfBuf
	p.prevRpcPermissionConfBuf = p.rpcPermissionConfBuf

	proxy := p.backends
	b, err := yaml.Marshal(proxy)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	p.proxyConfBuf = b
	if err := ioutil.WriteFile(filepath.Join(p.dir, "proxies.yaml"), b, 0644); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	role := p.roles
	b, err = yaml.Marshal(role)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	p.roleConfBuf = b
	if err := ioutil.WriteFile(filepath.Join(p.dir, "roles.yaml"), b, 0644); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	rpcPermission := make([]*config.RpcPermission, 0)
	b, err = yaml.Marshal(rpcPermission)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	p.rpcPermissionConfBuf = b
	if err := ioutil.WriteFile(filepath.Join(p.dir, "rpc_permissions.yaml"), b, 0644); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	conf := &configv2.Config{
		AccessProxy: &configv2.AccessProxy{
			HTTP: &configv2.AuthProxyHTTP{
				ServerName:      fmt.Sprintf("e2e.f110.dev:%d", p.proxyPort),
				Bind:            fmt.Sprintf(":%d", p.proxyPort),
				BindInternalApi: fmt.Sprintf(":%d", p.internalPort),
				Certificate: &configv2.Certificate{
					CertFile: "./tls.crt",
					KeyFile:  "./tls.key",
				},
				Session: &configv2.Session{
					Type:    "secure_cookie",
					KeyFile: "./cookie_secret",
				},
			},
			Credential: &configv2.Credential{
				SigningPrivateKeyFile: "./privatekey.pem",
				InternalTokenFile:     "./internal_token",
			},
			RPCServer: fmt.Sprintf("127.0.0.1:%d", p.rpcPort),
			ProxyFile: "./proxies.yaml",
		},
		CertificateAuthority: &configv2.CertificateAuthority{
			Local: &configv2.CertificateAuthorityLocal{
				CertFile:         "./ca.crt",
				KeyFile:          "./ca.key",
				Organization:     "test",
				OrganizationUnit: "e2e",
				Country:          "jp",
			},
		},
		AuthorizationEngine: &configv2.AuthorizationEngine{
			RoleFile:          "./roles.yaml",
			RPCPermissionFile: "./rpc_permissions.yaml",
			RootUsers:         []string{"root@e2e.f110.dev"},
		},
		Logger: &configv2.Logger{
			Encoding: "console",
			Level:    "debug",
		},
		RPCServer: &configv2.RPCServer{
			Bind: fmt.Sprintf(":%d", p.rpcPort),
		},
		IdentityProvider: &configv2.IdentityProvider{
			Provider:         "custom",
			Issuer:           p.identityProvider.Issuer,
			ClientId:         "identityprovider",
			ClientSecretFile: "./identityprovider",
			RedirectUrl:      fmt.Sprintf("https://e2e.f110.dev:%d/auth/callback", p.proxyPort),
		},
		Datastore: &configv2.Datastore{
			DatastoreEtcd: &configv2.DatastoreEtcd{
				RawUrl:  "etcd://embed",
				DataDir: "./data",
			},
		},
		Dashboard: &configv2.Dashboard{
			Bind: fmt.Sprintf(":%d", p.dashboardPort),
		},
	}

	b, err = yaml.Marshal(conf)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	p.configBuf = b
	if err := ioutil.WriteFile(filepath.Join(p.dir, "config.yaml"), b, 0644); err != nil {
		return err
	}

	return nil
}
