package rpcserver

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.f110.dev/protoc-ddl/probe"
	"go.f110.dev/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	"go.f110.dev/heimdallr/pkg/auth"
	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/config/configutil"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/database/etcd"
	"go.f110.dev/heimdallr/pkg/database/mysql"
	"go.f110.dev/heimdallr/pkg/database/mysql/dao"
	"go.f110.dev/heimdallr/pkg/database/mysql/entity"
	"go.f110.dev/heimdallr/pkg/fsm"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/rpc/rpcserver"
)

const (
	datastoreTypeEtcd  = "etcd"
	datastoreTypeMySQL = "mysql"
)

const (
	stateInit fsm.State = iota
	stateSetup
	stateStart
	stateShutdown
)

type mainProcess struct {
	*fsm.FSM

	ConfFile       string
	Config         *configv2.Config
	configReloader *configutil.Reloader

	server *rpcserver.Server

	datastoreType   string
	etcdClient      *clientv3.Client
	conn            *sql.DB
	ca              *cert.CertificateAuthority
	userDatabase    database.UserDatabase
	clusterDatabase database.ClusterDatabase
	caDatabase      database.CertificateAuthority
	tokenDatabase   database.TokenDatabase
	relayLocator    database.RelayLocator

	mu    sync.Mutex
	ready bool
}

func New() *mainProcess {
	m := &mainProcess{}
	m.FSM = fsm.NewFSM(
		map[fsm.State]fsm.StateFunc{
			stateInit:     m.init,
			stateSetup:    m.setup,
			stateStart:    m.start,
			stateShutdown: m.shutdown,
		},
		stateInit,
		stateShutdown,
	)

	return m
}

func (m *mainProcess) init() (fsm.State, error) {
	conf, err := configutil.ReadConfig(m.ConfFile)
	if err != nil {
		return fsm.UnknownState, err
	}
	m.Config = conf
	m.configReloader, err = configutil.NewReloader(conf)
	if err != nil {
		return fsm.UnknownState, err
	}

	switch {
	case m.Config.Datastore.DatastoreEtcd != nil:
		m.datastoreType = datastoreTypeEtcd
	case m.Config.Datastore.DatastoreMySQL != nil:
		m.datastoreType = datastoreTypeMySQL
	}

	return stateSetup, nil
}

func (m *mainProcess) setup() (fsm.State, error) {
	if err := logger.Init(m.Config.Logger); err != nil {
		return fsm.UnknownState, err
	}

	switch m.datastoreType {
	case datastoreTypeEtcd:
		ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelFunc()

		client, err := m.Config.Datastore.GetEtcdClient(m.Config.Logger)
		if err != nil {
			return fsm.UnknownState, err
		}
		go m.watchGRPCConnState(client.ActiveConnection())
		m.etcdClient = client

		m.userDatabase, err = etcd.NewUserDatabase(ctx, client, database.SystemUser)
		if err != nil {
			return fsm.UnknownState, err
		}
		m.caDatabase = etcd.NewCA(client)
		m.clusterDatabase, err = etcd.NewClusterDatabase(ctx, client)
		if err != nil {
			return fsm.UnknownState, err
		}

		if m.Config.AccessProxy.HTTP.Bind != "" {
			m.tokenDatabase = etcd.NewTemporaryToken(client)
			m.relayLocator, err = etcd.NewRelayLocator(ctx, client)
			if err != nil {
				return fsm.UnknownState, err
			}
		}
	case datastoreTypeMySQL:
		m.datastoreType = datastoreTypeMySQL
		conn, err := sql.Open("mysql", m.Config.Datastore.DSN.FormatDSN())
		if err != nil {
			return fsm.UnknownState, xerrors.WithStack(err)
		}
		m.conn = conn

		repository := dao.NewRepository(conn)
		m.userDatabase = mysql.NewUserDatabase(repository, database.SystemUser)
		m.caDatabase = mysql.NewCA(repository)
		m.clusterDatabase, err = mysql.NewCluster(repository)
		if err != nil {
			return fsm.UnknownState, err
		}

		if m.Config.AccessProxy.HTTP.Bind != "" {
			m.tokenDatabase = mysql.NewTokenDatabase(repository)
			m.relayLocator = mysql.NewRelayLocator(repository)
		}
	default:
		return fsm.UnknownState, xerrors.New("cmd/rpcserver: required external datastore")
	}

	if m.Config.CertificateAuthority != nil {
		ca, err := cert.NewCertificateAuthority(m.caDatabase, m.Config.CertificateAuthority)
		if err != nil {
			return fsm.UnknownState, err
		}
		m.ca = ca
	}

	m.server = rpcserver.NewServer(
		m.Config,
		m.userDatabase,
		m.tokenDatabase,
		m.clusterDatabase,
		m.relayLocator,
		m.ca,
		m.IsReady,
	)

	auth.Init(m.Config, nil, m.userDatabase, m.tokenDatabase, nil)
	return stateStart, nil
}

func (m *mainProcess) start() (fsm.State, error) {
	go func() {
		if err := m.server.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "%+v\n", err)
		}
	}()

	if m.datastoreType == datastoreTypeEtcd {
		c, err := etcd.NewCompactor(m.etcdClient)
		if err != nil {
			return fsm.UnknownState, err
		}

		go func() {
			c.Start(context.Background())
		}()
	}

	return fsm.WaitState, nil
}

func (m *mainProcess) shutdown() (fsm.State, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelFunc()

	if m.server != nil {
		if err := m.server.Shutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "%+v\n", err)
		}
	}
	if m.relayLocator != nil {
		v, ok := m.relayLocator.(*etcd.RelayLocator)
		if ok {
			v.Close()
		}
	}

	return fsm.CloseState, nil
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
