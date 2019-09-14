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
	"github.com/f110/lagrangian-proxy/pkg/dashboard"
	"github.com/f110/lagrangian-proxy/pkg/database/etcd"
	"github.com/f110/lagrangian-proxy/pkg/frontproxy"
	"github.com/f110/lagrangian-proxy/pkg/identityprovider"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/session"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

type mainProcess struct {
	Stop context.CancelFunc

	ctx          context.Context
	wg           sync.WaitGroup
	config       *config.Config
	userDatabase *etcd.UserDatabase
	caDatabase   *etcd.CA
	sessionStore session.Store

	front     *frontproxy.FrontendProxy
	idp       *identityprovider.Server
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
	if m.front != nil {
		if err := m.front.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "%+v\n", err)
		}
	}
	if m.idp != nil {
		if err := m.idp.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "%+v\n", err)
		}
	}
	if m.dashboard != nil {
		if err := m.dashboard.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "%+v\n", err)
		}
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
				ctx, cancelFunc := context.WithTimeout(m.ctx, 30*time.Second)
				m.shutdown(ctx)
				cancelFunc()
				return
			}
		}
	}()
}

func (m *mainProcess) startFrontendProxy() {
	m.front = frontproxy.NewFrontendProxy(m.config)
	if err := m.front.Serve(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	}
}

func (m *mainProcess) startIdentityProviderServer() {
	server, err := identityprovider.NewServer(m.config.IdentityProvider, m.userDatabase, m.sessionStore)
	if err != nil {
		m.Stop()
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		return
	}
	m.idp = server
	if err := m.idp.Start(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	}
}

func (m *mainProcess) startDashboard() {
	server := dashboard.NewServer(m.config, m.userDatabase, m.caDatabase)
	m.dashboard = server
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
	m.userDatabase = etcd.NewUserDatabase(client)
	m.caDatabase = etcd.NewCA(m.config.General.CertificateAuthority, client)
	switch m.config.FrontendProxy.Session.Type {
	case config.SessionTypeSecureCookie:
		m.sessionStore = session.NewSecureCookieStore(m.config.FrontendProxy.Session.HashKey, m.config.FrontendProxy.Session.BlockKey)
	}

	auth.Init(m.config, m.sessionStore, m.userDatabase)
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

		m.startIdentityProviderServer()
	}()

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
