package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
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
	"github.com/f110/lagrangian-proxy/pkg/server"
	"github.com/f110/lagrangian-proxy/pkg/server/ct"
	"github.com/f110/lagrangian-proxy/pkg/server/identityprovider"
	"github.com/f110/lagrangian-proxy/pkg/server/internalapi"
	"github.com/f110/lagrangian-proxy/pkg/server/rpc"
	"github.com/f110/lagrangian-proxy/pkg/server/token"
	"github.com/f110/lagrangian-proxy/pkg/session"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
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

	server      *server.Server
	internalApi *server.Internal
	dashboard   *dashboard.Server
	etcd        *embed.Etcd

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

func (m *mainProcess) shutdown(ctx context.Context) {
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

	client, _ := m.config.Datastore.GetEtcdClient()
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
				m.shutdown(ctx)
				cancelFunc()
				return
			}
		}
	}()
}

func (m *mainProcess) IsReady() bool {
	return m.readiness.IsReady() && m.clusterDatabase.Alive()
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
	rpcServer := rpc.NewServer(m.config, m.userDatabase, m.clusterDatabase)

	s := server.New(m.config, m.clusterDatabase, front, rpcServer, m.connector, idp, t, resourceServer, ctReport)
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
	dashboardServer := dashboard.NewServer(m.config, m.userDatabase, m.caDatabase)
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
	client, err := m.config.Datastore.GetEtcdClient()
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

	m.userDatabase, err = etcd.NewUserDatabase(context.Background(), client)
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

		switch m.config.FrontendProxy.Session.Type {
		case config.SessionTypeSecureCookie:
			m.sessionStore = session.NewSecureCookieStore(m.config.FrontendProxy.Session.HashKey, m.config.FrontendProxy.Session.BlockKey)
		case config.SessionTypeMemcached:
			m.sessionStore = session.NewMemcachedStore(m.config.FrontendProxy.Session)
		}

		m.connector = connector.NewServer(m.config, m.caDatabase, m.relayLocator)
	}

	auth.Init(m.config, m.sessionStore, m.userDatabase, m.caDatabase, m.tokenDatabase)
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

func command(args []string) error {
	confFile := ""
	fs := pflag.NewFlagSet("lagrangian-proxy", pflag.ContinueOnError)
	fs.StringVarP(&confFile, "config", "c", confFile, "Config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mainProcess := newMainProcess()
	if err := mainProcess.ReadConfig(confFile); err != nil {
		return err
	}
	if err := mainProcess.Setup(); err != nil {
		return err
	}

	if err := mainProcess.Start(); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	mainProcess.Wait()
	mainProcess.WaitShutdown()

	return nil
}

func main() {
	if err := command(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
