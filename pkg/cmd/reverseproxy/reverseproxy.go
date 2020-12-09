package reverseproxy

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
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
	"go.f110.dev/heimdallr/pkg/auth/authz"
	"go.f110.dev/heimdallr/pkg/authproxy"
	"go.f110.dev/heimdallr/pkg/cert"
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

type state int
type stateFunc func() error

const (
	stateInit state = iota
	stateSetup
	stateStartRPCServer
	stateSetupRPCConn
	stateRun
	stateShuttingDown
	stateWaitServerShutdown
	stateShuttingDownRPCServer
	stateWaitRPCServerShutdown
	stateEmbedEtcdShutdown
	stateWaitEtcdShutdown
	stateFinish
)

const (
	datastoreTypeEtcd  = "etcd"
	datastoreTypeMySQL = "mysql"
	datastoreNone      = "none"
)

type mainProcess struct {
	ConfFile string

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

	rpcServerConn *grpc.ClientConn
	revokedCert   *rpcclient.RevokedCertificateWatcher

	server      *server.Server
	internalApi *server.Internal
	dashboard   *dashboard.Server
	rpcServer   *rpcserver.Server

	etcd *embed.Etcd

	mu    sync.Mutex
	ready bool

	stateCh         chan state
	rpcServerDoneCh chan struct{}
}

func New() *mainProcess {
	m := &mainProcess{
		stateCh: make(chan state),
	}

	m.signalHandling()
	return m
}

func (m *mainProcess) NextState(state state) error {
	m.stateCh <- state
	return nil
}

func (m *mainProcess) Loop() {
	go func() {
		m.stateCh <- stateInit
	}()

	for {
		s := <-m.stateCh

		var fn stateFunc
		switch s {
		case stateInit:
			fn = m.ReadConfig
		case stateSetup:
			fn = m.Setup
		case stateStartRPCServer:
			fn = m.StartRPCServer
		case stateSetupRPCConn:
			fn = m.SetupAfterStartingRPCServer
		case stateRun:
			fn = m.Start
		case stateShuttingDown:
			fn = m.Shutdown
		case stateWaitServerShutdown:
			fn = m.WaitShutdown
		case stateShuttingDownRPCServer:
			fn = m.ShutdownRPCServer
		case stateWaitRPCServerShutdown:
			fn = m.WaitRPCServerShutdown
		case stateEmbedEtcdShutdown:
			fn = m.ShutdownEtcd
		case stateWaitEtcdShutdown:
			fn = m.WaitEtcdShutdown
		case stateFinish:
			return
		}

		go func() {
			if err := fn(); err != nil {
				fmt.Fprintf(os.Stderr, "%+v\n", err)
				_ = m.NextState(stateShuttingDown)
			}
		}()
	}
}

func (m *mainProcess) ReadConfig() error {
	conf, err := configutil.ReadConfig(m.ConfFile)
	if err != nil {
		return err
	}
	m.config = conf
	m.configReloader, err = configutil.NewReloader(conf)
	if err != nil {
		return err
	}

	if m.config.Datastore.DatastoreEtcd != nil {
		m.datastoreType = datastoreTypeEtcd
	} else if m.config.Datastore.DatastoreMySQL != nil {
		m.datastoreType = datastoreTypeMySQL
	} else {
		m.datastoreType = datastoreNone
	}

	return m.NextState(stateSetup)
}

func (m *mainProcess) Shutdown() error {
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

	go func() {
		wg.Wait()
		done <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		logger.Log.Info("Shutdown phase is timed out")
	case <-done:
	}

	return m.NextState(stateWaitServerShutdown)
}

func (m *mainProcess) WaitShutdown() error {
	m.wg.Wait()
	return m.NextState(stateShuttingDownRPCServer)
}

func (m *mainProcess) WaitRPCServerShutdown() error {
	if m.rpcServerDoneCh != nil {
		<-m.rpcServerDoneCh
	}
	return m.NextState(stateEmbedEtcdShutdown)
}

func (m *mainProcess) ShutdownRPCServer() error {
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

	return m.NextState(stateWaitRPCServerShutdown)
}

func (m *mainProcess) ShutdownEtcd() error {
	if m.etcd != nil {
		m.etcd.Server.Stop()
	}

	return m.NextState(stateWaitEtcdShutdown)
}

func (m *mainProcess) signalHandling() {
	signalCh := make(chan os.Signal)
	signal.Notify(signalCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		for sig := range signalCh {
			switch sig {
			case syscall.SIGTERM, os.Interrupt:
				_ = m.NextState(stateShuttingDown)
				return
			}
		}
	}()
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
	s := server.NewInternal(m.config, internalApi, internalProbe, internalProf)
	m.internalApi = s
	if err := m.internalApi.Start(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	}
}

func (m *mainProcess) startDashboard() {
	dashboardServer := dashboard.NewServer(m.config, m.rpcServerConn)
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

func (m *mainProcess) Setup() error {
	if err := logger.Init(m.config.Logger); err != nil {
		return xerrors.Errorf(": %v", err)
	}

	if m.config.Datastore.DatastoreEtcd != nil && m.config.Datastore.DatastoreEtcd.Embed {
		if err := m.startEmbedEtcd(); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	switch m.datastoreType {
	case datastoreTypeEtcd:
		ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelFunc()

		client, err := m.config.Datastore.GetEtcdClient(m.config.Logger)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		go m.watchGRPCConnState(client.ActiveConnection())

		m.etcdClient = client

		m.userDatabase, err = etcd.NewUserDatabase(ctx, client, database.SystemUser)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		caDatabase, err := etcd.NewCA(ctx, client)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		m.ca = cert.NewCertificateAuthority(caDatabase, m.config.CertificateAuthority)
		m.clusterDatabase, err = etcd.NewClusterDatabase(context.Background(), client)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}

		if m.config.AccessProxy.HTTP.Bind != "" {
			m.tokenDatabase = etcd.NewTemporaryToken(client)
			m.relayLocator, err = etcd.NewRelayLocator(ctx, client)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
		}
	case datastoreTypeMySQL:
		conn, err := m.config.Datastore.GetMySQLConn()
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		repository := dao.NewRepository(conn)
		m.userDatabase = mysql.NewUserDatabase(repository, database.SystemUser)
		caDatabase := mysql.NewCA(repository)
		m.ca = cert.NewCertificateAuthority(caDatabase, m.config.CertificateAuthority)
		m.clusterDatabase, err = mysql.NewCluster(repository)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		if m.config.AccessProxy.HTTP.Bind != "" {
			m.tokenDatabase = mysql.NewTokenDatabase(repository)
			m.relayLocator = mysql.NewRelayLocator(repository)
		}
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

	auth.InitInterceptor(m.config, m.userDatabase, m.tokenDatabase)
	return m.NextState(stateStartRPCServer)
}

func (m *mainProcess) SetupAfterStartingRPCServer() error {
	rpcclient.OverrideGrpcLogger()

	cred := credentials.NewTLS(&tls.Config{ServerName: rpc.ServerHostname, RootCAs: m.config.CertificateAuthority.Local.CertPool})
	conn, err := grpc.Dial(
		m.config.AccessProxy.RPCServer,
		grpc.WithTransportCredentials(cred),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: time.Second, PermitWithoutStream: true}),
		grpc.WithStreamInterceptor(grpc_retry.StreamClientInterceptor()),
		grpc.WithUnaryInterceptor(grpc_retry.UnaryClientInterceptor()),
	)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	m.rpcServerConn = conn

	if m.config.AccessProxy.HTTP.Bind != "" {
		m.connector = connector.NewServer(m.config, m.rpcServerConn, m.relayLocator)
	}

	m.revokedCert, err = rpcclient.NewRevokedCertificateWatcher(conn, m.config.AccessProxy.Credential.InternalToken)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	auth.Init(m.config, m.sessionStore, m.userDatabase, m.tokenDatabase, m.revokedCert)
	authz.Init(m.config)
	return m.NextState(stateRun)
}

func (m *mainProcess) StartRPCServer() error {
	if m.config.RPCServer != nil && m.config.RPCServer.Bind != "" {
		errCh := make(chan error)

		m.rpcServerDoneCh = make(chan struct{})
		go func() {
			defer func() {
				close(errCh)
				m.rpcServerDoneCh <- struct{}{}
			}()

			m.rpcServer = rpcserver.NewServer(m.config, m.userDatabase, m.tokenDatabase, m.clusterDatabase, m.relayLocator, m.ca, m.IsReady)
			if err := m.rpcServer.Start(); err != nil {
				errCh <- err
			}
		}()

		successCh := make(chan struct{})
		go func() {
			logger.Log.Debug("Waiting for start rpcserver")
			if err := netutil.WaitListen(m.config.RPCServer.Bind, time.Second); err != nil {
				errCh <- err
				return
			}
			successCh <- struct{}{}
		}()

		select {
		case err := <-errCh:
			return err
		case <-successCh:
		}

		if m.datastoreType == datastoreTypeEtcd {
			c, err := etcd.NewCompactor(m.etcdClient)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			go c.Start(context.Background())
		}
	}

	return m.NextState(stateSetupRPCConn)
}

func (m *mainProcess) Start() error {
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
			return xerrors.Errorf(": %v", err)
		}
		if err := netutil.WaitListen(m.config.AccessProxy.HTTP.BindInternalApi, time.Second); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	if m.config.Dashboard.Bind != "" {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()

			m.startDashboard()
		}()

		if err := netutil.WaitListen(m.config.Dashboard.Bind, time.Second); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	return nil
}

func (m *mainProcess) WaitEtcdShutdown() error {
	if m.etcd != nil {
		<-m.etcd.Server.StopNotify()
		logger.Log.Debug("Shutdown embed etcd")
	}

	return m.NextState(stateFinish)
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
