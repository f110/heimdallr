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
	"github.com/f110/lagrangian-proxy/pkg/server/identityprovider"
	"github.com/f110/lagrangian-proxy/pkg/server/internalapi"
	"github.com/f110/lagrangian-proxy/pkg/server/token"
	"github.com/f110/lagrangian-proxy/pkg/session"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

type mainProcess struct {
	Stop context.CancelFunc

	ctx           context.Context
	wg            sync.WaitGroup
	config        *config.Config
	userDatabase  *etcd.UserDatabase
	caDatabase    database.CertificateAuthority
	tokenDatabase database.TokenDatabase
	relayLocator  database.RelayLocator
	sessionStore  session.Store
	connector     *connector.Server

	front     *frontproxy.FrontendProxy
	server    *server.Server
	dashboard *dashboard.Server
	etcd      *embed.Etcd
}

func newMainProcess() *mainProcess {
	ctx, cancelFunc := context.WithCancel(context.Background())
	m := &mainProcess{Stop: cancelFunc, ctx: ctx}

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
	if m.front != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.front.Shutdown(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "%+v\n", err)
			}
		}()
	}
	if m.server != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.server.Shutdown(ctx); err != nil {
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

func (m *mainProcess) startFrontendProxy() {
	m.front = frontproxy.NewFrontendProxy(m.config, m.connector)
	if err := m.front.Serve(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	}
}

func (m *mainProcess) startUIServer() {
	idp, err := identityprovider.NewServer(m.config.IdentityProvider, m.userDatabase, m.sessionStore)
	if err != nil {
		m.Stop()
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		return
	}
	t := token.New(m.config, m.sessionStore, m.tokenDatabase)
	internalApi := internalapi.NewServer()
	resourceServer := internalapi.NewResourceServer(m.config)
	probe := internalapi.NewProbe(make(chan struct{}))

	s := server.New(m.config, m.connector, idp, t, internalApi, resourceServer, probe)
	m.server = s
	if err := m.server.Start(); err != nil && err != http.ErrServerClosed {
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

func (m *mainProcess) startCrawler() {
	crawler := database.NewTokenCrawler(m.tokenDatabase)
	crawler.Crawl(m.ctx)
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
	m.userDatabase, err = etcd.NewUserDatabase(context.Background(), client)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	m.caDatabase, err = etcd.NewCA(context.Background(), m.config.General.CertificateAuthority, client)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	switch m.config.FrontendProxy.Session.Type {
	case config.SessionTypeSecureCookie:
		m.sessionStore = session.NewSecureCookieStore(m.config.FrontendProxy.Session.HashKey, m.config.FrontendProxy.Session.BlockKey)
	case config.SessionTypeMemcached:
		m.sessionStore = session.NewMemcachedStore(m.config.FrontendProxy.Session)
	}
	m.tokenDatabase = etcd.NewTemporaryToken(client)
	m.relayLocator, err = etcd.NewRelayLocator(context.Background(), client)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	m.connector = connector.NewServer(m.config, m.caDatabase, m.relayLocator)

	auth.Init(m.config, m.sessionStore, m.userDatabase, m.caDatabase, m.tokenDatabase)
	return nil
}

func (m *mainProcess) Start() error {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()

		m.startFrontendProxy()
	}()

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()

		m.startUIServer()
	}()

	if m.config.Dashboard.Enable {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()

			m.startDashboard()
		}()
	}

	if m.config.Datastore.Embed {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()

			m.startCrawler()
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
