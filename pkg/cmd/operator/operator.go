package operator

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/pflag"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"go.f110.dev/heimdallr/pkg/fsm"
	clientset "go.f110.dev/heimdallr/pkg/k8s/client/versioned"
	"go.f110.dev/heimdallr/pkg/k8s/controllers"
	informers "go.f110.dev/heimdallr/pkg/k8s/informers/externalversions"
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

	ctx        context.Context
	cancel     context.CancelFunc
	coreClient *kubernetes.Clientset
	client     *clientset.Clientset
	restCfg    *rest.Config

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
		return fsm.UnknownState, errors.New("--key is mandatory if the webhook is enabed")
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
	kubeconfigPath := ""
	if m.dev {
		h, err := os.UserHomeDir()
		if err != nil {
			return fsm.UnknownState, err
		}
		kubeconfigPath = filepath.Join(h, ".kube", "config")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return fsm.UnknownState, err
	}
	m.restCfg = cfg

	m.coreClient, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		return fsm.UnknownState, err
	}
	m.client, err = clientset.NewForConfig(cfg)
	if err != nil {
		return fsm.UnknownState, err
	}

	return stateStartProbe, nil
}

func (m *mainProcess) startProbe() (fsm.State, error) {
	probe := controllers.NewProbe(m.probeAddr)
	go probe.Start()
	probe.Ready()

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

	select {
	case <-elected:
	case <-m.ctx.Done():
		return fsm.UnknownState, nil
	}

	return stateStartWorkers, nil
}

func (m *mainProcess) startWorkers() (fsm.State, error) {
	coreSharedInformerFactory := kubeinformers.NewSharedInformerFactory(m.coreClient, 30*time.Second)
	sharedInformerFactory := informers.NewSharedInformerFactory(m.client, 30*time.Second)

	c, err := controllers.NewProxyController(sharedInformerFactory, coreSharedInformerFactory, m.coreClient, m.client)
	if err != nil {
		return fsm.UnknownState, err
	}
	m.proxy = c

	e, err := controllers.NewEtcdController(
		sharedInformerFactory,
		coreSharedInformerFactory,
		m.coreClient,
		m.client,
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

	g, err := controllers.NewGitHubController(sharedInformerFactory, coreSharedInformerFactory, m.coreClient, m.client, http.DefaultTransport)
	if err != nil {
		return fsm.UnknownState, err
	}
	m.g = g

	ic := controllers.NewIngressController(coreSharedInformerFactory, sharedInformerFactory, m.coreClient, m.client)
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
	sharedInformerFactory.Start(m.ctx.Done())

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

func (m *mainProcess) Flags(fs *pflag.FlagSet) {
	fs.StringVar(&m.id, "id", m.id, "the holder identity name")
	fs.StringVar(&m.metricsAddr, "metrics-addr", m.metricsAddr, "The address the metric endpoint binds to.")
	fs.StringVar(&m.leaseLockName, "lease-lock-name", m.leaseLockName, "the lease lock resource name")
	fs.StringVar(&m.leaseLockNamespace, "lease-lock-namespace", m.leaseLockNamespace, "the lease lock resource namespace")
	fs.StringVar(&m.clusterDomain, "cluster-domain", m.clusterDomain, "Cluster domain")
	fs.StringVar(&m.probeAddr, "probe-addr", m.probeAddr, "Listen addr that provides readiness probe")
	fs.IntVar(&m.workers, "workers", m.workers, "The number of workers on each controller")
	fs.BoolVar(&m.dev, "dev", m.dev, "development mode")
	fs.BoolVar(&m.disableWebhook, "disable-webhook", m.disableWebhook, "Disable webhook server")
	fs.StringVar(&m.certFile, "cert", m.certFile, "Server certificate file for webhook")
	fs.StringVar(&m.keyFile, "key", m.keyFile, "Private key for server certificate")

	logger.Flags(fs)
}
