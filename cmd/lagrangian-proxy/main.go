package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/embed"
	"github.com/f110/lagrangian-proxy/pkg/auth"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/config/configreader"
	"github.com/f110/lagrangian-proxy/pkg/connector"
	"github.com/f110/lagrangian-proxy/pkg/dashboard"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/database/etcd"
	"github.com/f110/lagrangian-proxy/pkg/frontproxy"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc/rpcclient"
	"github.com/f110/lagrangian-proxy/pkg/rpc/rpcserver"
	"github.com/f110/lagrangian-proxy/pkg/server"
	"github.com/f110/lagrangian-proxy/pkg/server/ct"
	"github.com/f110/lagrangian-proxy/pkg/server/identityprovider"
	"github.com/f110/lagrangian-proxy/pkg/server/internalapi"
	"github.com/f110/lagrangian-proxy/pkg/server/token"
	"github.com/f110/lagrangian-proxy/pkg/session"
	"github.com/f110/lagrangian-proxy/pkg/version"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

type mainProcess struct {
	Stop context.CancelFunc

	ctx             context.Context
	wg              sync.WaitGroup
	config          *config.Config
	etcdClient      *clientv3.Client
	userDatabase    database.UserDatabase
	caDatabase      database.CertificateAuthority
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

	probeCh   chan struct{}
	readiness *etcd.TapReadiness
}

func newMainProcess() *mainProcess {
	ctx, cancelFunc := context.WithCancel(context.Background())
	m := &mainProcess{Stop: cancelFunc, ctx: ctx, probeCh: make(chan struct{})}

	m.signalHandling()
	return m
}

func (m *mainProcess) ReadConfig(p string) error {
	conf, err := configreader.ReadConfig(p)
	if err != nil {
		return err
	}
	m.config = conf

	return nil
}

func (m *mainProcess) Shutdown(ctx context.Context) {
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

	if m.rpcServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := m.rpcServer.Shutdown(ctx); err != nil {
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

	client, _ := m.config.Datastore.GetEtcdClient(m.config.Logger)
	if err := client.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	}
	if m.etcd != nil {
		m.etcd.Server.Stop()
	}
}

func (m *mainProcess) signalHandling() {
	signalCh := make(chan os.Signal)
	signal.Notify(signalCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		for sig := range signalCh {
			switch sig {
			case syscall.SIGTERM, os.Interrupt:
				m.Stop()
				ctx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
				m.Shutdown(ctx)
				cancelFunc()
				return
			}
		}
	}()
}

func (m *mainProcess) IsReady() bool {
	if !m.revokedCert.IsReady() {
		logger.Log.Warn("Revoked certificate watcher error", zap.Error(m.revokedCert.Error()))
	}
	return m.readiness.IsReady() && m.clusterDatabase.Alive() && m.revokedCert.IsReady()
}

func (m *mainProcess) startServer() {
	front := frontproxy.NewFrontendProxy(m.config, m.connector)
	idp, err := identityprovider.NewServer(m.config, m.userDatabase, m.sessionStore)
	if err != nil {
		m.Stop()
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		return
	}
	t := token.New(m.config, m.sessionStore, m.tokenDatabase)
	resourceServer := internalapi.NewResourceServer(m.config)
	ctReport := ct.NewServer()

	s := server.New(m.config, m.clusterDatabase, front, m.connector, idp, t, resourceServer, ctReport)
	m.server = s
	if err := m.server.Start(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	}
}

func (m *mainProcess) startInternalApiServer() {
	internalApi := internalapi.NewServer()
	probe := internalapi.NewProbe(m.IsReady)
	s := server.NewInternal(m.config, internalApi, probe)
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
	c.LogPkgLevels = "*=C"
	c.LPUrls[0].Host = "localhost:0"
	c.LCUrls[0] = *m.config.Datastore.EtcdUrl
	c.SetupLogging()

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

	if m.config.Datastore.Embed {
		if err := m.startEmbedEtcd(); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}

	if m.config.Datastore.Url != nil {
		client, err := m.config.Datastore.GetEtcdClient(m.config.Logger)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		m.readiness = &etcd.TapReadiness{
			Watcher: etcd.NewTapWatcher(client.Watcher),
			Lease:   etcd.NewTapLease(client.Lease),
		}
		client.Watcher = m.readiness.Watcher
		client.Lease = m.readiness.Lease
		m.etcdClient = client

		m.userDatabase, err = etcd.NewUserDatabase(context.Background(), client, database.SystemUser)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		m.caDatabase, err = etcd.NewCA(context.Background(), m.config.General.CertificateAuthority, client)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		m.clusterDatabase, err = etcd.NewClusterDatabase(context.Background(), client)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}

		if m.config.General.Enable {
			m.tokenDatabase = etcd.NewTemporaryToken(client)
			m.relayLocator, err = etcd.NewRelayLocator(context.Background(), client)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
		}
	}

	if m.config.General.Enable {
		switch m.config.FrontendProxy.Session.Type {
		case config.SessionTypeSecureCookie:
			m.sessionStore = session.NewSecureCookieStore(m.config.FrontendProxy.Session.HashKey, m.config.FrontendProxy.Session.BlockKey)
		case config.SessionTypeMemcached:
			m.sessionStore = session.NewMemcachedStore(m.config.FrontendProxy.Session)
		}

		m.connector = connector.NewServer(m.config, m.caDatabase, m.relayLocator)
	}

	auth.InitInterceptor(m.config, m.userDatabase, m.tokenDatabase)
	return nil
}

func (m *mainProcess) SetupAfterStartingRPCServer() error {
	rpcclient.OverrideGrpcLogger()
	cred := credentials.NewTLS(&tls.Config{ServerName: m.config.General.ServerNameHost, RootCAs: m.config.General.CertificateAuthority.CertPool})
	conn, err := grpc.Dial(
		m.config.General.RpcTarget,
		grpc.WithTransportCredentials(cred),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: time.Second, PermitWithoutStream: true}),
	)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	m.rpcServerConn = conn
	m.revokedCert, err = rpcclient.NewRevokedCertificateWatcher(conn, m.config.General.SigningPrivateKey)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	auth.Init(m.config, m.sessionStore, m.userDatabase, m.tokenDatabase, m.revokedCert)
	return nil
}

func (m *mainProcess) StartRPCServer() error {
	if m.config.RPCServer.Enable {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()

			m.rpcServer = rpcserver.NewServer(m.config, m.userDatabase, m.tokenDatabase, m.clusterDatabase, m.relayLocator, m.caDatabase)
			if err := m.rpcServer.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "%+v\n", err)
			}
		}()

		logger.Log.Debug("Waiting for start rpcserver")
		retry := 0
		for {
			if retry > 10 {
				return xerrors.New("main: waiting for start rpcserver is timed out")
			}

			conn, err := net.DialTimeout("tcp", m.config.RPCServer.Bind, 10*time.Millisecond)
			if err != nil {
				retry++
				time.Sleep(10 * time.Millisecond)
				continue
			}
			conn.Close()
			break
		}

		c, err := etcd.NewCompactor(m.etcdClient)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		go c.Start(context.Background())
	}

	return nil
}

func (m *mainProcess) Start() error {
	if m.config.General.Enable {
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
	}

	if m.config.Dashboard.Enable {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()

			m.startDashboard()
		}()
	}

	return nil
}

func (m *mainProcess) Wait() {
	m.wg.Wait()
}

func (m *mainProcess) WaitShutdown() {
	if m.etcd != nil {
		<-m.etcd.Server.StopNotify()
		logger.Log.Debug("Shutdown embed etcd")
	}
}

func printVersion() {
	fmt.Printf("Version: %s\n", version.Version)
	fmt.Printf("Go version: %s\n", runtime.Version())
}

func command(args []string) error {
	confFile := ""
	version := false
	fs := pflag.NewFlagSet("lagrangian-proxy", pflag.ContinueOnError)
	fs.StringVarP(&confFile, "config", "c", confFile, "Config file")
	fs.BoolVarP(&version, "version", "v", version, "Show version")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if version {
		printVersion()
		return nil
	}

	process := newMainProcess()
	if err := process.ReadConfig(confFile); err != nil {
		return err
	}
	if err := process.Setup(); err != nil {
		return err
	}
	if err := process.StartRPCServer(); err != nil {
		return err
	}
	if err := process.SetupAfterStartingRPCServer(); err != nil {
		return err
	}

	if err := process.Start(); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	process.Wait()
	process.WaitShutdown()

	return nil
}

func main() {
	if err := command(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
