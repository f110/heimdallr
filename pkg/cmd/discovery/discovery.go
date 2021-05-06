package discovery

import (
	"context"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/pflag"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"go.f110.dev/heimdallr/pkg/fsm"
	"go.f110.dev/heimdallr/pkg/k8s/dns"
	"go.f110.dev/heimdallr/pkg/logger"
)

const (
	stateInit fsm.State = iota
	stateStart
	stateShutdown
)

type mainProcess struct {
	*fsm.FSM

	port          int
	namespace     string
	clusterDomain string
	ttl           int
	dev           bool
	readyFile     string

	sharedInformerFactory informers.SharedInformerFactory
	dnsServer             *dns.Sidecar
}

func New() *mainProcess {
	m := &mainProcess{}
	m.FSM = fsm.NewFSM(
		map[fsm.State]fsm.StateFunc{
			stateInit:     m.init,
			stateStart:    m.start,
			stateShutdown: m.shutdown,
		},
		stateInit,
		stateShutdown,
	)
	return m
}

func (m *mainProcess) Flags(fs *pflag.FlagSet) {
	fs.IntVar(&m.port, "port", 8200, "Listen port")
	fs.StringVar(&m.namespace, "namespace", "", "Namespace")
	fs.StringVar(&m.clusterDomain, "cluster-domain", "", "Cluster domain suffix")
	fs.IntVar(&m.ttl, "ttl", 10, "DNS Record TTL")
	fs.StringVar(&m.readyFile, "ready-file", "", "Status file path. After booting, creating an empty file.")
	fs.BoolVar(&m.dev, "dev", false, "Development mode")
}

func (m *mainProcess) init() (fsm.State, error) {
	// At this time, already parsed command line arguments.
	if err := logger.InitByFlags(); err != nil {
		return fsm.UnknownState, xerrors.Errorf(": %w", err)
	}

	kubeconfigPath := ""
	if m.dev {
		h, err := os.UserHomeDir()
		if err != nil {
			return fsm.UnknownState, xerrors.Errorf(": %w", err)
		}
		kubeconfigPath = filepath.Join(h, ".kube", "config")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return fsm.UnknownState, xerrors.Errorf(": %w", err)
	}

	coreClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fsm.UnknownState, xerrors.Errorf(": %w", err)
	}
	m.sharedInformerFactory = informers.NewSharedInformerFactoryWithOptions(coreClient, 0, informers.WithNamespace(m.namespace))

	s, err := dns.NewSidecar(fmt.Sprintf(":%d", m.port), m.sharedInformerFactory, m.namespace, m.clusterDomain, m.ttl)
	if err != nil {
		return fsm.UnknownState, xerrors.Errorf(": %w", err)
	}
	m.dnsServer = s

	go func() {
		http.HandleFunc("/liveness", func(w http.ResponseWriter, req *http.Request) {})
		http.HandleFunc("/readiness", func(w http.ResponseWriter, req *http.Request) {})

		logger.Log.Info("Listen pprof and probe", zap.Int("port", 8080))
		err := http.ListenAndServe(":8080", nil)
		if err != nil && err != http.ErrServerClosed {
			logger.Log.Warn("Failed listen", zap.Error(err))
		}
	}()

	return stateStart, nil
}

func (m *mainProcess) start() (fsm.State, error) {
	m.sharedInformerFactory.Start(context.Background().Done())
	if _, err := os.Stat(m.readyFile); !os.IsNotExist(err) {
		logger.Log.Info("Delete readiness file before start DNS server", zap.String("path", m.readyFile))
		if err := os.Remove(m.readyFile); err != nil {
			return fsm.UnknownState, xerrors.Errorf(": %w", err)
		}
	}

	logger.Log.Info("Start DNS server", zap.Int("port", m.port))
	go m.dnsServer.Start()

	logger.Log.Debug("Waiting for booting")
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("udp", fmt.Sprintf(":%d", m.port))
		},
	}
	t := time.NewTicker(1000 * time.Millisecond)
Wait:
	for {
		select {
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 1000*time.Millisecond)
			addrs, err := r.LookupIPAddr(ctx, "ready.local.")
			if err != nil {
				cancel()
				logger.Log.Debug("Occurred error", zap.Error(err))
				continue
			}
			if len(addrs) == 0 {
				cancel()
				logger.Log.Debug("empty response")
				continue
			}
			if addrs[0].IP.Equal(net.IPv4(127, 0, 1, 1)) {
				cancel()
				break Wait
			}
			cancel()
			logger.Log.Debug("Unexpected response", zap.Any("addrs", addrs))
		}
	}

	if m.readyFile != "" {
		logger.Log.Debug("Create file", zap.String("path", m.readyFile))
		_, err := os.Create(m.readyFile)
		if err != nil {
			return fsm.UnknownState, xerrors.Errorf(": %w", err)
		}
	}

	return fsm.WaitState, nil
}

func (m *mainProcess) shutdown() (fsm.State, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := m.dnsServer.Shutdown(ctx); err != nil {
		return fsm.UnknownState, xerrors.Errorf(": %w", err)
	}
	cancel()

	_ = os.Remove(m.readyFile)
	return fsm.CloseState, nil
}
