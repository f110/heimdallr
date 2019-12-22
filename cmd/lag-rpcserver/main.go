package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/f110/lagrangian-proxy/pkg/auth"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/config/configreader"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/database/etcd"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc/rpcserver"
	"github.com/f110/lagrangian-proxy/pkg/version"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
)

type mainProcess struct {
	Config *config.Config

	ctx    context.Context
	server *rpcserver.Server

	etcdClient      *clientv3.Client
	readiness       *etcd.TapReadiness
	userDatabase    database.UserDatabase
	caDatabase      database.CertificateAuthority
	clusterDatabase database.ClusterDatabase
	tokenDatabase   database.TokenDatabase
	relayLocator    database.RelayLocator

	Stop context.CancelFunc
	wg   sync.WaitGroup
	err  error
}

func newMainProcess() *mainProcess {
	ctx, cancelFunc := context.WithCancel(context.Background())
	return &mainProcess{ctx: ctx, Stop: cancelFunc}
}

func (m *mainProcess) ReadConfig(p string) error {
	conf, err := configreader.ReadConfig(p)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	m.Config = conf

	return nil
}

func (m *mainProcess) Setup() error {
	if err := logger.Init(m.Config.Logger); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if m.Config.Datastore.Url != nil {
		client, err := m.Config.Datastore.GetEtcdClient(m.Config.Logger)
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
		m.caDatabase, err = etcd.NewCA(context.Background(), m.Config.General.CertificateAuthority, client)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		m.clusterDatabase, err = etcd.NewClusterDatabase(context.Background(), client)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}

		if m.Config.General.Enable {
			m.tokenDatabase = etcd.NewTemporaryToken(client)
			m.relayLocator, err = etcd.NewRelayLocator(context.Background(), client)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
		}
	} else {
		return xerrors.New("lag-rpcserver: required external datastore")
	}

	m.server = rpcserver.NewServer(m.Config, m.userDatabase, m.tokenDatabase, m.clusterDatabase, m.relayLocator, m.caDatabase)

	auth.InitInterceptor(m.Config, m.userDatabase, m.tokenDatabase)
	return nil
}

func (m *mainProcess) Start() error {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()

		if err := m.server.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "%+v\n", err)
			m.err = err
			m.Stop()
		}
	}()

	c, err := etcd.NewCompactor(m.etcdClient)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()

		if err := c.Start(context.Background()); err != nil {
			m.err = err
			m.Stop()
		}
	}()

	return nil
}

func (m *mainProcess) Wait() {
	m.wg.Wait()
}

func (m *mainProcess) Shutdown(ctx context.Context) {
	if err := m.server.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	}
}

func (m *mainProcess) signalHandling() {
	signalCh := make(chan os.Signal)
	signal.Notify(signalCh, syscall.SIGTERM, syscall.SIGINT)

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
}

func printVersion() {
	fmt.Printf("Version: %s\n", version.Version)
	fmt.Printf("Go version: %s\n", runtime.Version())
}

func rpcServer(args []string) error {
	confFile := ""
	v := false
	fs := pflag.NewFlagSet("lag-rpcserver", pflag.ContinueOnError)
	fs.StringVarP(&confFile, "config", "c", confFile, "Config file")
	fs.BoolVarP(&v, "version", "v", v, "Show version")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if v {
		printVersion()
		return nil
	}

	process := newMainProcess()
	if err := process.ReadConfig(confFile); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if err := process.Setup(); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if err := process.Start(); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	process.Wait()

	return process.err
}

func main() {
	if err := rpcServer(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
