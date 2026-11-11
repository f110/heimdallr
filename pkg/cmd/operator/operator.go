package operator

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.f110.dev/kubeproto/go/apis/metav1"
	"go.f110.dev/kubeproto/go/k8sclient"
	"go.f110.dev/xerrors"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"sigs.k8s.io/structured-merge-diff/v6/fieldpath"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/fsm"
	"go.f110.dev/heimdallr/pkg/k8s/api/etcdv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxy"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxyv1alpha2"
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
	stateStartWebhook
	stateLeaderElection
	stateMigrate
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
	watchNamespace     string
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
	coreClient       *k8sclient.Set
	k8sCoreClient    kubernetes.Interface
	client           *client.Set
	thirdPartyClient *thirdpartyclient.Set
	restCfg          *rest.Config

	probeServer   *controllers.Probe
	webhookServer *webhook.Server

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
		stateStartWebhook:   m.startWebhook,
		stateLeaderElection: m.leaderElection,
		stateMigrate:        m.migrate,
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
		return fsm.UnknownState, xerrors.WithStack(err)
	}
	cfg.UserAgent = controllers.FieldManager
	m.restCfg = cfg

	m.k8sCoreClient, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		return fsm.UnknownState, xerrors.WithStack(err)
	}
	m.client, err = client.NewSet(cfg)
	if err != nil {
		return fsm.UnknownState, xerrors.WithStack(err)
	}
	m.coreClient, err = k8sclient.NewSet(cfg)
	if err != nil {
		return fsm.UnknownState, xerrors.WithStack(err)
	}
	m.thirdPartyClient, err = thirdpartyclient.NewSet(cfg)
	if err != nil {
		return fsm.UnknownState, xerrors.WithStack(err)
	}

	return stateStartProbe, nil
}

func (m *mainProcess) startProbe() (fsm.State, error) {
	m.probeServer = controllers.NewProbe(m.probeAddr)
	go m.probeServer.Start()

	return stateStartWebhook, nil
}

func (m *mainProcess) startWebhook() (fsm.State, error) {
	if m.disableWebhook {
		m.probeServer.Ready()
		return stateLeaderElection, nil
	}

	ws := webhook.NewServer(":8080", m.certFile, m.keyFile)
	if err := ws.Listen(); err != nil {
		return fsm.UnknownState, err
	}
	m.webhookServer = ws
	go func() {
		err := ws.Start()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Log.Info("Failed start webhook server", slog.Any("error", err))
		}
	}()

	m.probeServer.Ready()

	return stateLeaderElection, nil
}

func (m *mainProcess) leaderElection() (fsm.State, error) {
	// In development mode, we don't attempt the leader election.
	if m.dev {
		return stateMigrate, nil
	}

	lock := &resourcelock.LeaseLock{
		LeaseMeta: k8smetav1.ObjectMeta{
			Name:      m.leaseLockName,
			Namespace: m.leaseLockNamespace,
		},
		Client: m.k8sCoreClient.CoordinationV1(),
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

	return stateMigrate, nil
}

// migrate runs the migrations which have to be finished before starting the controllers.
func (m *mainProcess) migrate() (fsm.State, error) {
	migrations := []func(context.Context) error{
		m.migrateManagedFields,
	}
	for _, v := range migrations {
		if err := v(m.ctx); err != nil {
			return fsm.UnknownState, err
		}
	}

	return stateStartWorkers, nil
}

// migrateManagedFields transfers the ownership of the fields which the older operator has updated without Server-Side Apply
// to controllers.FieldManager.
// Otherwise, the fields which the operator no longer sets aren't removed by Server-Side Apply.
func (m *mainProcess) migrateManagedFields(ctx context.Context) error {
	ns := m.watchNamespace
	opts := metav1.ListOptions{}

	deployments, err := m.coreClient.AppsV1.ListDeployment(ctx, ns, opts)
	if err != nil {
		return xerrors.WithStack(err)
	}
	if err := upgradeManagedFieldsOf(ctx, filter(deployments.Items, isControlledByOperator), m.coreClient.AppsV1.UpdateDeployment); err != nil {
		return err
	}
	pdbs, err := m.coreClient.PolicyV1.ListPodDisruptionBudget(ctx, ns, opts)
	if err != nil {
		return xerrors.WithStack(err)
	}
	if err := upgradeManagedFieldsOf(ctx, filter(pdbs.Items, isControlledByOperator), m.coreClient.PolicyV1.UpdatePodDisruptionBudget); err != nil {
		return err
	}
	services, err := m.coreClient.CoreV1.ListService(ctx, ns, opts)
	if err != nil {
		return xerrors.WithStack(err)
	}
	if err := upgradeManagedFieldsOf(ctx, filter(services.Items, isControlledByOperator), m.coreClient.CoreV1.UpdateService); err != nil {
		return err
	}
	configMaps, err := m.coreClient.CoreV1.ListConfigMap(ctx, ns, opts)
	if err != nil {
		return xerrors.WithStack(err)
	}
	if err := upgradeManagedFieldsOf(ctx, filter(configMaps.Items, isControlledByOperator), m.coreClient.CoreV1.UpdateConfigMap); err != nil {
		return err
	}
	cronJobs, err := m.coreClient.BatchV1.ListCronJob(ctx, ns, opts)
	if err != nil {
		return xerrors.WithStack(err)
	}
	if err := upgradeManagedFieldsOf(ctx, filter(cronJobs.Items, isControlledByOperator), m.coreClient.BatchV1.UpdateCronJob); err != nil {
		return err
	}
	etcdClusters, err := m.client.EtcdV1alpha2.ListEtcdCluster(ctx, ns, opts)
	if err != nil {
		return xerrors.WithStack(err)
	}
	if err := upgradeManagedFieldsOf(ctx, filter(etcdClusters.Items, isControlledByOperator), m.client.EtcdV1alpha2.UpdateEtcdCluster); err != nil {
		return err
	}
	backends, err := m.client.ProxyV1alpha2.ListBackend(ctx, ns, opts)
	if err != nil {
		return xerrors.WithStack(err)
	}
	if err := upgradeManagedFieldsOf(ctx, filter(backends.Items, isCreatedByIngressController), m.client.ProxyV1alpha2.UpdateBackend); err != nil {
		return err
	}

	// The custom resources of the third party may not be installed.
	certificates, err := m.thirdPartyClient.CertManagerV1.ListCertificate(ctx, ns, opts)
	if err != nil && !apierrors.IsNotFound(err) {
		return xerrors.WithStack(err)
	}
	if err == nil {
		if err := upgradeManagedFieldsOf(ctx, filter(certificates.Items, isControlledByOperator), m.thirdPartyClient.CertManagerV1.UpdateCertificate); err != nil {
			return err
		}
	}
	serviceMonitors, err := m.thirdPartyClient.CoreV1.ListServiceMonitor(ctx, ns, opts)
	if err != nil && !apierrors.IsNotFound(err) {
		return xerrors.WithStack(err)
	}
	if err == nil {
		if err := upgradeManagedFieldsOf(ctx, filter(serviceMonitors.Items, isControlledByOperator), m.thirdPartyClient.CoreV1.UpdateServiceMonitor); err != nil {
			return err
		}
	}
	podMonitors, err := m.thirdPartyClient.CoreV1.ListPodMonitor(ctx, ns, opts)
	if err != nil && !apierrors.IsNotFound(err) {
		return xerrors.WithStack(err)
	}
	if err == nil {
		if err := upgradeManagedFieldsOf(ctx, filter(podMonitors.Items, isControlledByOperator), m.thirdPartyClient.CoreV1.UpdatePodMonitor); err != nil {
			return err
		}
	}

	return nil
}

func (m *mainProcess) startWorkers() (fsm.State, error) {
	coreSharedInformerFactory := k8sclient.NewInformerFactory(m.coreClient, k8sclient.NewInformerCache(), m.watchNamespace, 30*time.Second)
	factory := client.NewInformerFactory(m.client, client.NewInformerCache(), m.watchNamespace, 30*time.Second)

	c, err := controllers.NewProxyController(m.ctx, factory, coreSharedInformerFactory, m.watchNamespace, m.coreClient, m.client, m.thirdPartyClient, m.k8sCoreClient)
	if err != nil {
		return fsm.UnknownState, err
	}
	m.proxy = c

	e, err := controllers.NewEtcdController(
		factory,
		coreSharedInformerFactory,
		m.watchNamespace,
		m.coreClient,
		m.client.EtcdV1alpha2,
		m.k8sCoreClient,
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

	g, err := controllers.NewGitHubController(factory, coreSharedInformerFactory, m.watchNamespace, m.coreClient, m.client.ProxyV1alpha2, m.k8sCoreClient, http.DefaultTransport)
	if err != nil {
		return fsm.UnknownState, err
	}
	m.g = g

	ic := controllers.NewIngressController(coreSharedInformerFactory, factory, m.watchNamespace, m.coreClient, m.client.ProxyV1alpha2, m.k8sCoreClient)
	m.ic = ic

	coreSharedInformerFactory.Run(m.ctx)
	factory.Run(m.ctx)

	c.Run(m.ctx, m.workers)
	e.Run(m.ctx, m.workers)
	g.Run(m.ctx, m.workers)
	ic.Run(m.ctx, m.workers)

	return fsm.WaitState, nil
}

func (m *mainProcess) shutdown() (fsm.State, error) {
	m.cancel()

	if m.webhookServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := m.webhookServer.Shutdown(ctx); err != nil {
			logger.Log.Info("Failed shutdown webhook server", slog.Any("error", err))
		}
		cancel()
	}
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
	fs.String("namespace", "The namespace that the operator watches. All namespaces are watched if empty").Var(&m.watchNamespace).Default(m.watchNamespace)
	fs.String("cluster-domain", "Cluster domain").Var(&m.clusterDomain).Default(m.clusterDomain)
	fs.String("probe-addr", "Listen addr that provides readiness probe").Var(&m.probeAddr).Default(m.probeAddr)
	fs.Int("workers", "The number of workers on each controller").Var(&m.workers).Default(m.workers)
	fs.Bool("dev", "development mode").Var(&m.dev).Default(m.dev)
	fs.Bool("disable-webhook", "Disable webhook server").Var(&m.disableWebhook).Default(m.disableWebhook)
	fs.String("cert", "Server certificate file for webhook").Var(&m.certFile).Default(m.certFile)
	fs.String("key", "Private key for server certificate").Var(&m.keyFile).Default(m.keyFile)

	logger.Flags(fs)
}

// legacyFieldManagers are the names that were recorded when the operator updated the objects before using Server-Side Apply.
var legacyFieldManagers = map[string]struct{}{"heimdallrcontroller": {}, "Go-http-client": {}}

// ownerAPIGroups are the API groups of the objects which control the objects applied by the operator.
var ownerAPIGroups = map[string]struct{}{proxyv1alpha2.GroupName: {}, etcdv1alpha2.GroupName: {}}

var finalizersPath = fieldpath.NewSet(fieldpath.MakePathOrDie("metadata", "finalizers"))

// filter returns the pointers to the items which f returns true.
func filter[E any, T interface {
	*E
	metav1.Object
}](items []E, f func(metav1.Object) bool) []T {
	filtered := make([]T, 0, len(items))
	for i := range items {
		if v := T(&items[i]); f(v) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func upgradeManagedFieldsOf[T metav1.Object](ctx context.Context, items []T, update func(context.Context, T, metav1.UpdateOptions) (T, error)) error {
	for _, v := range items {
		managedFields, upgraded, err := upgradeManagedFields(v.GetObjectMeta().ManagedFields)
		if err != nil {
			return err
		}
		if !upgraded {
			continue
		}
		v.GetObjectMeta().ManagedFields = managedFields
		if _, err := update(ctx, v, metav1.UpdateOptions{}); err != nil {
			return xerrors.WithStack(err)
		}
	}

	return nil
}

// isControlledByOperator returns true if the controller of obj is the custom resource of the operator.
// The legacy field manager "Go-http-client" is the default User-Agent of Go, so the objects which aren't created by the operator have to be excluded.
func isControlledByOperator(obj metav1.Object) bool {
	for _, v := range obj.GetObjectMeta().OwnerReferences {
		if !v.Controller {
			continue
		}
		gv, err := schema.ParseGroupVersion(v.APIVersion)
		if err != nil {
			continue
		}
		if _, ok := ownerAPIGroups[gv.Group]; ok {
			return true
		}
	}

	return false
}

func isCreatedByIngressController(obj metav1.Object) bool {
	_, ok := obj.GetObjectMeta().Annotations[proxy.AnnotationKeyIngressName]
	return ok
}

// upgradeManagedFields merges the fields of the entries of legacyFieldManagers into the entry of controllers.FieldManager
// and removes the entries of legacyFieldManagers.
// The fields of the entries which have the different API version from the entry of controllers.FieldManager are discarded
// because the field paths may differ between the versions.
// The ownership of finalizers isn't transferred because the controllers still add finalizers by Update.
func upgradeManagedFields(entries []metav1.ManagedFieldsEntry) ([]metav1.ManagedFieldsEntry, bool, error) {
	var applied *metav1.ManagedFieldsEntry
	var legacy []metav1.ManagedFieldsEntry
	upgraded := make([]metav1.ManagedFieldsEntry, 0, len(entries))
	for _, v := range entries {
		if v.Subresource != "" {
			upgraded = append(upgraded, v)
			continue
		}

		_, isLegacy := legacyFieldManagers[v.Manager]
		switch {
		case isLegacy && v.Operation == metav1.ManagedFieldsOperationTypeUpdate:
			legacy = append(legacy, v)
		case applied == nil && v.Manager == controllers.FieldManager && v.Operation == metav1.ManagedFieldsOperationTypeApply:
			applied = &v
		default:
			upgraded = append(upgraded, v)
		}
	}
	if len(legacy) == 0 {
		return nil, false, nil
	}
	if applied == nil {
		applied = &metav1.ManagedFieldsEntry{
			Manager:    controllers.FieldManager,
			Operation:  metav1.ManagedFieldsOperationTypeApply,
			APIVersion: legacy[0].APIVersion,
			Time:       legacy[0].Time,
			FieldsType: legacy[0].FieldsType,
		}
	}

	fields, err := decodeFieldsV1(applied)
	if err != nil {
		return nil, false, err
	}
	for _, v := range legacy {
		if v.APIVersion != applied.APIVersion {
			continue
		}
		s, err := decodeFieldsV1(&v)
		if err != nil {
			return nil, false, err
		}
		fields = fields.Union(s)
	}
	raw, err := fields.RecursiveDifference(finalizersPath).ToJSON()
	if err != nil {
		return nil, false, xerrors.WithStack(err)
	}
	applied.FieldsV1 = &metav1.FieldsV1{Raw: raw}

	return append(upgraded, *applied), true, nil
}

func decodeFieldsV1(entry *metav1.ManagedFieldsEntry) (*fieldpath.Set, error) {
	s := &fieldpath.Set{}
	if entry.FieldsV1 == nil {
		return s, nil
	}
	if err := s.FromJSON(bytes.NewReader(entry.FieldsV1.Raw)); err != nil {
		return nil, xerrors.WithStack(err)
	}
	return s, nil
}
