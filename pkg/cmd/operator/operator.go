package operator

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/fsm"
	"go.f110.dev/heimdallr/pkg/k8s/client"
	"go.f110.dev/heimdallr/pkg/k8s/controllers"
	"go.f110.dev/heimdallr/pkg/k8s/thirdpartyclient"
	"go.f110.dev/heimdallr/pkg/k8s/webhook"
	"go.f110.dev/heimdallr/pkg/logger"
)

const (
	stateInit fsm.State = iota
	stateSetup
	stateStartProbe
	stateLeaderElection
	stateStartWorkers
	stateShutdown
)

type mainProcess struct {
	*fsm.FSM

	id                 string
	metricsAddr        string
	kubeconfigPath     string
	leaseLockName      string
	leaseLockNamespace string
	clusterDomain      string
	probeAddr          string
	workers            int
	disableWebhook     bool
	certFile           string
	keyFile            string
	logLevel           string
	logEncoding        string
	dev                bool

	ctx              context.Context
	cancel           context.CancelFunc
	coreClient       *kubernetes.Clientset
	client           *client.Set
	thirdPartyClient *thirdpartyclient.Set
	restCfg          *rest.Config

	probeServer *controllers.Probe

	e     *controllers.EtcdController
	proxy *controllers.ProxyController
	g     *controllers.GitHubController
	ic    *controllers.IngressController
}

func New() *mainProcess {
	ctx, cancel := context.WithCancel(context.Background())
	m := &mainProcess{
		// Default option values
		id:          uuid.New().String(),
		workers:     1,
		metricsAddr: ":8080",
		probeAddr:   ":6000",

		ctx:    ctx,
		cancel: cancel,
	}

	m.FSM = fsm.NewFSM(map[fsm.State]fsm.StateFunc{
		stateInit:           m.init,
		stateSetup:          m.setup,
		stateStartProbe:     m.startProbe,
		stateLeaderElection: m.leaderElection,
		stateStartWorkers:   m.startWorkers,
		stateShutdown:       m.shutdown,
	},
		stateInit,
		stateShutdown,
	)

	return m
}

func (m *mainProcess) init() (fsm.State, error) {
	if !m.disableWebhook && m.certFile == "" {
		return fsm.UnknownState, errors.New("--cert is mandatory if the webhook is enabled")
	}
	if !m.disableWebhook && m.keyFile == "" {
		return fsm.UnknownState, errors.New("--key is mandatory if the webhook is enabled")
	}

	if err := logger.InitByFlags(); err != nil {
		return fsm.UnknownState, err
	}
	if err := logger.OverrideKlog(); err != nil {
		return fsm.UnknownState, err
	}

	return stateSetup, nil
}

func (m *mainProcess) setup() (fsm.State, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", m.kubeconfigPath)
	if err != nil {
		return fsm.UnknownState, err
	}
	m.restCfg = cfg

	m.coreClient, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		return fsm.UnknownState, err
	}
	m.client, err = client.NewSet(cfg)
	if err != nil {
		return fsm.UnknownState, err
	}
	m.thirdPartyClient, err = thirdpartyclient.NewSet(cfg)

	return stateStartProbe, nil
}

func (m *mainProcess) startProbe() (fsm.State, error) {
	m.probeServer = controllers.NewProbe(m.probeAddr)
	go m.probeServer.Start()

	return stateLeaderElection, nil
}

func (m *mainProcess) leaderElection() (fsm.State, error) {
	// In development mode, we don't attempt the leader election.
	if m.dev {
		return stateStartWorkers, nil
	}

	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      m.leaseLockName,
			Namespace: m.leaseLockNamespace,
		},
		Client: m.coreClient.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: m.id,
		},
	}

	elected := make(chan struct{})
	e, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   30 * time.Second,
		RenewDeadline:   15 * time.Second,
		RetryPeriod:     5 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(_ context.Context) {
				close(elected)
			},
			OnStoppedLeading: func() {
				m.FSM.Shutdown()
			},
			OnNewLeader: func(_ string) {},
		},
	})
	if err != nil {
		return stateShutdown, err
	}
	go e.Run(m.ctx)
	m.probeServer.Ready()

	select {
	case <-elected:
	case <-m.ctx.Done():
		return fsm.UnknownState, nil
	}

	return stateStartWorkers, nil
}

func (m *mainProcess) startWorkers() (fsm.State, error) {
	coreSharedInformerFactory := kubeinformers.NewSharedInformerFactory(m.coreClient, 30*time.Second)
	factory := client.NewInformerFactory(m.client, client.NewInformerCache(), metav1.NamespaceAll, 30*time.Second)

	c, err := controllers.NewProxyController(factory, coreSharedInformerFactory, m.coreClient, m.client, m.thirdPartyClient)
	if err != nil {
		return fsm.UnknownState, err
	}
	m.proxy = c

	e, err := controllers.NewEtcdController(
		factory,
		coreSharedInformerFactory,
		m.coreClient,
		m.client.EtcdV1alpha2,
		m.restCfg,
		m.clusterDomain,
		m.dev,
		http.DefaultTransport,
		nil,
	)
	if err != nil {
		return fsm.UnknownState, err
	}
	m.e = e

	g, err := controllers.NewGitHubController(factory, coreSharedInformerFactory, m.coreClient, m.client.ProxyV1alpha2, http.DefaultTransport)
	if err != nil {
		return fsm.UnknownState, err
	}
	m.g = g

	ic := controllers.NewIngressController(coreSharedInformerFactory, factory, m.coreClient, m.client.ProxyV1alpha2)
	m.ic = ic

	if !m.disableWebhook {
		ws := webhook.NewServer(":8080", m.certFile, m.keyFile)
		go func() {
			err := ws.Start()
			if err != nil && err != http.ErrServerClosed {
				logger.Log.Info("Failed start webhook server", zap.Error(err))
			}
		}()
	}

	coreSharedInformerFactory.Start(m.ctx.Done())
	factory.Run(m.ctx)

	c.Run(m.ctx, m.workers)
	e.Run(m.ctx, m.workers)
	g.Run(m.ctx, m.workers)
	ic.Run(m.ctx, m.workers)

	return fsm.WaitState, nil
}

func (m *mainProcess) shutdown() (fsm.State, error) {
	m.cancel()

	if m.e != nil {
		m.e.Shutdown()
	}
	if m.proxy != nil {
		m.proxy.Shutdown()
	}
	if m.g != nil {
		m.g.Shutdown()
	}
	if m.ic != nil {
		m.ic.Shutdown()
	}

	return fsm.CloseState, nil
}

func (m *mainProcess) Flags(fs *cmd.FlagSet) {
	fs.String("id", "the holder identity name").Var(&m.id).Default(m.id)
	fs.String("kubeconfig", "Path to the kubeconfig file").Var(&m.kubeconfigPath).Default(m.kubeconfigPath)
	fs.String("metrics-addr", "The address the metric endpoint binds to.").Var(&m.metricsAddr).Default(m.metricsAddr)
	fs.String("lease-lock-name", "the lease lock resource name").Var(&m.leaseLockName).Default(m.leaseLockName)
	fs.String("lease-lock-namespace", "the lease lock resource namespace").Var(&m.leaseLockNamespace).Default(m.leaseLockNamespace)
	fs.String("cluster-domain", "Cluster domain").Var(&m.clusterDomain).Default(m.clusterDomain)
	fs.String("probe-addr", "Listen addr that provides readiness probe").Var(&m.probeAddr).Default(m.probeAddr)
	fs.Int("workers", "The number of workers on each controller").Var(&m.workers).Default(m.workers)
	fs.Bool("dev", "development mode").Var(&m.dev).Default(m.dev)
	fs.Bool("disable-webhook", "Disable webhook server").Var(&m.disableWebhook).Default(m.disableWebhook)
	fs.String("cert", "Server certificate file for webhook").Var(&m.certFile).Default(m.certFile)
	fs.String("key", "Private key for server certificate").Var(&m.keyFile).Default(m.keyFile)

	logger.Flags(fs)
}
