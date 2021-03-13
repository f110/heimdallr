package reverseproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/hashicorp/vault/api"
	"go.etcd.io/etcd/v3/clientv3"
	"go.etcd.io/etcd/v3/embed"
	"go.f110.dev/protoc-ddl/probe"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"go.f110.dev/heimdallr/pkg/auth"
	"go.f110.dev/heimdallr/pkg/authproxy"
	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/cert/vault"
	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/config/configutil"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/connector"
	"go.f110.dev/heimdallr/pkg/dashboard"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/database/etcd"
	"go.f110.dev/heimdallr/pkg/database/mysql"
	"go.f110.dev/heimdallr/pkg/database/mysql/dao"
	"go.f110.dev/heimdallr/pkg/database/mysql/entity"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/netutil"
	"go.f110.dev/heimdallr/pkg/rpc"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
	"go.f110.dev/heimdallr/pkg/rpc/rpcserver"
	"go.f110.dev/heimdallr/pkg/server"
	"go.f110.dev/heimdallr/pkg/server/ct"
	"go.f110.dev/heimdallr/pkg/server/identityprovider"
	"go.f110.dev/heimdallr/pkg/server/internalapi"
	"go.f110.dev/heimdallr/pkg/server/token"
	"go.f110.dev/heimdallr/pkg/session"
)

const (
	stateInit cmd.State = iota
	stateSetup
	stateStartRPCServer
	stateSetupRPCConn
	stateRun
	stateShuttingDown
	stateWaitServerShutdown
	stateShuttingDownRPCServer
	stateWaitRPCServerShutdown
	stateEmbedMiddlewareShutdown
	stateWaitMiddlewareShutdown
)

const (
	datastoreTypeEtcd  = "etcd"
	datastoreTypeMySQL = "mysql"
	datastoreNone      = "none"
)

type mainProcess struct {
	*cmd.FSM

	ConfFile string
	VaultBin string

	wg              sync.WaitGroup
	config          *configv2.Config
	configReloader  *configutil.Reloader
	datastoreType   string
	etcdClient      *clientv3.Client
	conn            *sql.DB
	ca              *cert.CertificateAuthority
	userDatabase    database.UserDatabase
	tokenDatabase   database.TokenDatabase
	relayLocator    database.RelayLocator
	clusterDatabase database.ClusterDatabase
	sessionStore    session.Store
	connector       *connector.Server
	vaultClient     *api.Client

	rpcServerConn *grpc.ClientConn
	revokedCert   *rpcclient.RevokedCertificateWatcher

	server      *server.Server
	internalApi *server.Internal
	dashboard   *dashboard.Server
	rpcServer   *rpcserver.Server

	etcd  *embed.Etcd
	vault *exec.Cmd

	mu    sync.Mutex
	ready bool

	rpcServerDoneCh chan struct{}
}

func New() *mainProcess {
	m := &mainProcess{}
	m.FSM = cmd.NewFSM(
		map[cmd.State]cmd.StateFunc{
			stateInit:                    m.init,
			stateSetup:                   m.setup,
			stateStartRPCServer:          m.startRPCServer,
			stateSetupRPCConn:            m.setupAfterStartingRPCServer,
			stateRun:                     m.run,
			stateShuttingDown:            m.shuttingDown,
			stateWaitServerShutdown:      m.waitServerShutdown,
			stateShuttingDownRPCServer:   m.shuttingDownRPCServer,
			stateWaitRPCServerShutdown:   m.waitRPCServerShutdown,
			stateEmbedMiddlewareShutdown: m.embedMiddlewareShutdown,
			stateWaitMiddlewareShutdown:  m.waitMiddlewareShutdown,
		},
		stateInit,
		stateShuttingDown,
	)

	return m
}

func (m *mainProcess) init() (cmd.State, error) {
	conf, err := configutil.ReadConfig(m.ConfFile)
	if err != nil {
		return cmd.UnknownState, err
	}
	m.config = conf
	m.configReloader, err = configutil.NewReloader(conf)
	if err != nil {
		return cmd.UnknownState, err
	}

	if m.config.Datastore.DatastoreEtcd != nil {
		m.datastoreType = datastoreTypeEtcd
	} else if m.config.Datastore.DatastoreMySQL != nil {
		m.datastoreType = datastoreTypeMySQL
	} else {
		m.datastoreType = datastoreNone
	}

	return stateSetup, nil
}

func (m *mainProcess) shuttingDown() (cmd.State, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelFunc()

	done := make(chan struct{})
	var wg sync.WaitGroup
	if m.server != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.server.Shutdown(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "%+v\n", err)
			}
		}()
	}

	if m.internalApi != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.internalApi.Shutdown(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "%+v\n", err)
			}
		}()
	}

	if m.dashboard != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.dashboard.Shutdown(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "%+v\n", err)
			}
		}()
	}

	if m.relayLocator != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, ok := m.relayLocator.(*etcd.RelayLocator)
			if ok {
				v.Close()
			}
		}()
	}

	go func() {
		wg.Wait()
		done <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		logger.Log.Info("Shutdown phase is timed out")
	case <-done:
	}

	return stateWaitServerShutdown, nil
}

func (m *mainProcess) waitServerShutdown() (cmd.State, error) {
	m.wg.Wait()
	return stateShuttingDownRPCServer, nil
}

func (m *mainProcess) waitRPCServerShutdown() (cmd.State, error) {
	if m.rpcServerDoneCh != nil {
		<-m.rpcServerDoneCh
	}
	return stateEmbedMiddlewareShutdown, nil
}

func (m *mainProcess) shuttingDownRPCServer() (cmd.State, error) {
	if m.config != nil {
		switch m.datastoreType {
		case datastoreTypeEtcd:
			client, _ := m.config.Datastore.GetEtcdClient(m.config.Logger)
			if err := client.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "%+v\n", err)
			}
		}
	}

	if m.rpcServer != nil {
		ctx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancelFunc()

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := m.rpcServer.Shutdown(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "%+v\n", err)
			}
		}()

		done := make(chan struct{})
		go func() {
			wg.Wait()
			done <- struct{}{}
		}()

		select {
		case <-ctx.Done():
			logger.Log.Info("Shutdown phase is timed out")
		case <-done:
		}
	}

	return stateWaitRPCServerShutdown, nil
}

func (m *mainProcess) embedMiddlewareShutdown() (cmd.State, error) {
	if m.etcd != nil {
		m.etcd.Server.Stop()
	}
	if m.vault != nil {
		if err := m.vault.Process.Signal(syscall.SIGTERM); err != nil {
			return cmd.UnknownState, xerrors.Errorf(": %w", err)
		}
	}

	return stateWaitMiddlewareShutdown, nil
}

func (m *mainProcess) IsReady() bool {
	switch m.datastoreType {
	case datastoreTypeEtcd:
		m.mu.Lock()
		defer m.mu.Unlock()

		return m.ready
	case datastoreTypeMySQL:
		p := probe.NewProbe(m.conn)
		ctx, cancelFunc := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancelFunc()

		return p.Ready(ctx, entity.SchemaHash)
	}

	return false
}

func (m *mainProcess) startServer() {
	rpcClient, err := rpcclient.NewWithInternalToken(m.rpcServerConn, m.config.AccessProxy.Credential.InternalToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		return
	}
	front := authproxy.NewAuthProxy(m.config, m.connector, rpcClient)

	idp, err := identityprovider.NewServer(m.config, m.userDatabase, m.sessionStore)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		return
	}
	t := token.New(m.config, m.sessionStore, m.tokenDatabase)
	resourceServer, err := internalapi.NewResourceServer(m.config, m.userDatabase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		return
	}
	ctReport := ct.NewServer()

	s := server.New(m.config, m.clusterDatabase, front, m.connector, idp, t, resourceServer, ctReport)
	m.server = s
	if err := m.server.Start(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	}
}

func (m *mainProcess) startInternalApiServer() {
	internalApi := internalapi.New()
	internalProbe := internalapi.NewProbe(m.IsReady)
	internalProf := internalapi.NewProf()
	resourceServer, err := internalapi.NewResourceServer(m.config, m.userDatabase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		return
	}

	s := server.NewInternal(m.config, internalApi, internalProbe, internalProf, resourceServer)
	m.internalApi = s
	if err := m.internalApi.Start(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	}
}

func (m *mainProcess) startDashboard() {
	dashboardServer, err := dashboard.NewServer(m.config, m.rpcServerConn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		return
	}

	m.dashboard = dashboardServer
	if err := m.dashboard.Start(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	}
}

func (m *mainProcess) startEmbedEtcd() error {
	c := embed.NewConfig()
	c.Dir = m.config.Datastore.DataDir
	c.LogLevel = "fatal"
	c.LPUrls[0].Host = "localhost:0"
	c.LCUrls[0] = *m.config.Datastore.EtcdUrl

	e, err := embed.StartEtcd(c)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	m.etcd = e

	select {
	case <-e.Server.ReadyNotify():
		logger.Log.Info("Start embed etcd", zap.String("url", c.LCUrls[0].String()))
	case <-time.After(10 * time.Second):
		logger.Log.Error("Failed start embed etcd")
		return xerrors.New("failed start embed etcd")
	}

	return nil
}

func (m *mainProcess) startVault() error {
	vaultPort, err := netutil.FindUnusedPort()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	r, w := io.Pipe()
	vaultCmd := exec.CommandContext(
		context.Background(),
		m.VaultBin,
		"server",
		"-dev",
		fmt.Sprintf("-dev-listen-address=127.0.0.1:%d", vaultPort),
	)
	vaultCmd.Stdout = w
	if err := vaultCmd.Start(); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	m.vault = vaultCmd
	logger.Log.Debug("Start Vault", zap.Int("pid", vaultCmd.Process.Pid), zap.Int("port", vaultPort))

	rootToken := ""
	scan := bufio.NewScanner(r)
	for scan.Scan() {
		line := scan.Text()
		if strings.HasPrefix(line, "Root Token:") {
			rootToken = strings.TrimSpace(strings.TrimPrefix(line, "Root Token: "))
			break
		}
	}
	logger.Log.Debug("Vault root token", zap.String("token", rootToken))

	m.config.CertificateAuthority.Vault.Addr = fmt.Sprintf("http://127.0.0.1:%d", vaultPort)
	m.config.CertificateAuthority.Vault.Token = rootToken
	vaultClient, err := vault.NewClient(m.config.CertificateAuthority.Vault.Addr, rootToken, "")
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := vaultClient.EnablePKI(context.TODO()); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	logger.Log.Debug("Enable PKI Engine", zap.String("path", "pki/"))

	var caCert *x509.Certificate
	var privateKey *rsa.PrivateKey
	if _, err := os.Stat(filepath.Join(m.config.CertificateAuthority.Vault.Dir, "vault_ca.crt")); os.IsNotExist(err) {
		crt, key, err := cert.CreateCertificateAuthority("Heimdallr with Vault", "", "", "", "rsa")
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		pemBundle := new(bytes.Buffer)
		if err := pem.Encode(pemBundle, &pem.Block{Bytes: crt.Raw, Type: "CERTIFICATE"}); err != nil {
			return xerrors.Errorf(": %w", err)
		}
		b, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		if err := pem.Encode(pemBundle, &pem.Block{Bytes: b, Type: "RSA PRIVATE KEY"}); err != nil {
			return xerrors.Errorf(": %w", err)
		}
		if err := os.WriteFile(
			filepath.Join(m.config.CertificateAuthority.Vault.Dir, "vault_ca.crt"),
			pemBundle.Bytes(),
			0400,
		); err != nil {
			return xerrors.Errorf(": %w", err)
		}
		caCert = crt
		privateKey = key.(*rsa.PrivateKey)
	} else {
		buf, err := os.ReadFile(filepath.Join(m.config.CertificateAuthority.Vault.Dir, "vault_ca.crt"))
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		for {
			b, rest := pem.Decode(buf)
			if b == nil {
				break
			}
			switch b.Type {
			case "CERTIFICATE":
				crt, err := x509.ParseCertificate(b.Bytes)
				if err != nil {
					return xerrors.Errorf(": %w", err)
				}
				caCert = crt
			case "RSA PRIVATE KEY":
				key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
				if err != nil {
					return xerrors.Errorf(": %w", err)
				}
				privateKey = key.(*rsa.PrivateKey)
			}
			buf = rest
		}
	}

	if err := vaultClient.SetCA(context.Background(), caCert, privateKey); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	m.config.CertificateAuthority.CertPool, err = vaultClient.GetCertPool(context.Background())
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	m.config.CertificateAuthority.Certificate, err = vaultClient.GetCACertificate(context.Background())
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	err = vaultClient.SetRole(context.Background(), m.config.CertificateAuthority.Vault.Role, &vault.Role{
		AllowedDomains:   []string{rpc.ServerHostname},
		AllowSubDomains:  true,
		AllowLocalhost:   true,
		AllowBareDomains: true,
		EnforceHostnames: false,
		ServerFlag:       true,
		ClientFlag:       true,
	})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (m *mainProcess) setup() (cmd.State, error) {
	if err := logger.Init(m.config.Logger); err != nil {
		return cmd.UnknownState, xerrors.Errorf(": %w", err)
	}

	if m.config.Datastore.DatastoreEtcd != nil && m.config.Datastore.DatastoreEtcd.Embed {
		if err := m.startEmbedEtcd(); err != nil {
			return cmd.UnknownState, xerrors.Errorf(": %w", err)
		}
	}

	if m.VaultBin != "" && m.config.CertificateAuthority.Vault != nil {
		if err := m.startVault(); err != nil {
			return cmd.UnknownState, xerrors.Errorf(": %w", err)
		}
	}

	var caDatabase database.CertificateAuthority
	switch m.datastoreType {
	case datastoreTypeEtcd:
		ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelFunc()

		client, err := m.config.Datastore.GetEtcdClient(m.config.Logger)
		if err != nil {
			return cmd.UnknownState, xerrors.Errorf(": %w", err)
		}
		go m.watchGRPCConnState(client.ActiveConnection())

		m.etcdClient = client

		m.userDatabase, err = etcd.NewUserDatabase(ctx, client, database.SystemUser)
		if err != nil {
			return cmd.UnknownState, xerrors.Errorf(": %w", err)
		}
		caDatabase, err = etcd.NewCA(ctx, client)
		if err != nil {
			return cmd.UnknownState, xerrors.Errorf(": %w", err)
		}
		m.clusterDatabase, err = etcd.NewClusterDatabase(context.Background(), client)
		if err != nil {
			return cmd.UnknownState, xerrors.Errorf(": %w", err)
		}

		if m.config.AccessProxy.HTTP.Bind != "" {
			m.tokenDatabase = etcd.NewTemporaryToken(client)
			m.relayLocator, err = etcd.NewRelayLocator(context.Background(), client)
			if err != nil {
				return cmd.UnknownState, xerrors.Errorf(": %w", err)
			}
		}
	case datastoreTypeMySQL:
		conn, err := m.config.Datastore.GetMySQLConn()
		if err != nil {
			return cmd.UnknownState, xerrors.Errorf(": %w", err)
		}

		repository := dao.NewRepository(conn)
		m.userDatabase = mysql.NewUserDatabase(repository, database.SystemUser)
		caDatabase = mysql.NewCA(repository)
		m.clusterDatabase, err = mysql.NewCluster(repository)
		if err != nil {
			return cmd.UnknownState, xerrors.Errorf(": %w", err)
		}

		if m.config.AccessProxy.HTTP.Bind != "" {
			m.tokenDatabase = mysql.NewTokenDatabase(repository)
			m.relayLocator = mysql.NewRelayLocator(repository)
		}
	}

	if m.config.CertificateAuthority != nil {
		ca, err := cert.NewCertificateAuthority(caDatabase, m.config.CertificateAuthority)
		if err != nil {
			return cmd.UnknownState, xerrors.Errorf(": %w", err)
		}
		m.ca = ca
	}

	if m.config.AccessProxy.HTTP.Bind != "" {
		switch m.config.AccessProxy.HTTP.Session.Type {
		case config.SessionTypeSecureCookie:
			m.sessionStore = session.NewSecureCookieStore(
				m.config.AccessProxy.HTTP.Session.HashKey,
				m.config.AccessProxy.HTTP.Session.BlockKey,
				m.config.AccessProxy.ServerNameHost,
			)
		case config.SessionTypeMemcached:
			m.sessionStore = session.NewMemcachedStore(m.config.AccessProxy.HTTP.Session)
		}
	}

	auth.Init(m.config, nil, m.userDatabase, m.tokenDatabase, nil)
	return stateStartRPCServer, nil
}

func (m *mainProcess) setupAfterStartingRPCServer() (cmd.State, error) {
	rpcclient.OverrideGrpcLogger()

	cred := credentials.NewTLS(&tls.Config{ServerName: rpc.ServerHostname, RootCAs: m.config.CertificateAuthority.CertPool})
	conn, err := grpc.Dial(
		m.config.AccessProxy.RPCServer,
		grpc.WithTransportCredentials(cred),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: time.Second, PermitWithoutStream: true}),
		grpc.WithStreamInterceptor(grpc_retry.StreamClientInterceptor()),
		grpc.WithUnaryInterceptor(grpc_retry.UnaryClientInterceptor()),
	)
	if err != nil {
		return cmd.UnknownState, xerrors.Errorf(": %v", err)
	}
	m.rpcServerConn = conn

	if m.config.AccessProxy.HTTP.Bind != "" {
		m.connector = connector.NewServer(m.config, m.rpcServerConn, m.relayLocator)
	}

	m.revokedCert, err = rpcclient.NewRevokedCertificateWatcher(conn, m.config.AccessProxy.Credential.InternalToken)
	if err != nil {
		return cmd.UnknownState, xerrors.Errorf(": %v", err)
	}

	auth.Init(m.config, m.sessionStore, m.userDatabase, m.tokenDatabase, m.revokedCert)
	return stateRun, nil
}

func (m *mainProcess) startRPCServer() (cmd.State, error) {
	if m.config.RPCServer != nil && m.config.RPCServer.Bind != "" {
		errCh := make(chan error)

		m.rpcServerDoneCh = make(chan struct{})
		go func() {
			defer func() {
				close(errCh)
				m.rpcServerDoneCh <- struct{}{}
			}()

			m.rpcServer = rpcserver.NewServer(
				m.config,
				m.userDatabase,
				m.tokenDatabase,
				m.clusterDatabase,
				m.relayLocator,
				m.ca,
				m.IsReady,
			)
			if err := m.rpcServer.Start(); err != nil {
				errCh <- err
			}
		}()

		successCh := make(chan struct{})
		go func() {
			logger.Log.Debug("Waiting for start rpcserver")
			if err := netutil.WaitListen(m.config.RPCServer.Bind, time.Second); err != nil {
				return
			}
			successCh <- struct{}{}
		}()

		select {
		case err := <-errCh:
			return cmd.UnknownState, err
		case <-successCh:
		}

		if m.datastoreType == datastoreTypeEtcd {
			c, err := etcd.NewCompactor(m.etcdClient)
			if err != nil {
				return cmd.UnknownState, xerrors.Errorf(": %v", err)
			}
			go c.Start(context.Background())
		}
	}

	return stateSetupRPCConn, nil
}

func (m *mainProcess) run() (cmd.State, error) {
	if m.config.AccessProxy.HTTP.Bind != "" {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()

			m.startServer()
		}()

		m.wg.Add(1)
		go func() {
			defer m.wg.Done()

			m.startInternalApiServer()
		}()

		if err := netutil.WaitListen(m.config.AccessProxy.HTTP.Bind, time.Second); err != nil {
			return cmd.UnknownState, xerrors.Errorf(": %v", err)
		}
		if err := netutil.WaitListen(m.config.AccessProxy.HTTP.BindInternalApi, time.Second); err != nil {
			return cmd.UnknownState, xerrors.Errorf(": %v", err)
		}
	}

	if m.config.Dashboard.Bind != "" {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()

			if err := netutil.WaitListen(m.config.AccessProxy.HTTP.BindInternalApi, 3*time.Second); err != nil {
				return
			}

			m.startDashboard()
		}()

		if err := netutil.WaitListen(m.config.Dashboard.Bind, 5*time.Second); err != nil {
			return cmd.UnknownState, xerrors.Errorf(": %v", err)
		}
	}

	return cmd.WaitState, nil
}

func (m *mainProcess) waitMiddlewareShutdown() (cmd.State, error) {
	if m.etcd != nil {
		<-m.etcd.Server.StopNotify()
		logger.Log.Debug("Shutdown embed etcd")
	}

	return cmd.CloseState, nil
}

func (m *mainProcess) watchGRPCConnState(conn *grpc.ClientConn) {
	state := conn.GetState()
	for conn.WaitForStateChange(context.Background(), state) {
		state = conn.GetState()
		m.mu.Lock()
		switch state {
		case connectivity.Ready:
			m.ready = true
		default:
			m.ready = false
		}
		m.mu.Unlock()
	}
}
