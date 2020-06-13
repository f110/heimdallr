package controllers

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	monitoringv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	mInformers "github.com/coreos/prometheus-operator/pkg/client/informers/externalversions"
	mListers "github.com/coreos/prometheus-operator/pkg/client/listers/monitoring/v1"
	mClientset "github.com/coreos/prometheus-operator/pkg/client/versioned"
	"github.com/google/go-cmp/cmp"
	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmClientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"golang.org/x/xerrors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	applisters "k8s.io/client-go/listers/apps/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	etcdv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha1"
	proxyv1 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
	"go.f110.dev/heimdallr/operator/pkg/client/versioned/scheme"
	informers "go.f110.dev/heimdallr/operator/pkg/informers/externalversions"
	etcdListers "go.f110.dev/heimdallr/operator/pkg/listers/etcd/v1alpha1"
	proxyListers "go.f110.dev/heimdallr/operator/pkg/listers/proxy/v1"
)

var (
	ErrEtcdClusterIsNotReady = errors.New("EtcdCluster is not ready yet")
	ErrRPCServerIsNotReady   = errors.New("rpc server is not ready")
)

type ProxyController struct {
	schema.GroupVersionKind

	client                 kubernetes.Interface
	serviceLister          listers.ServiceLister
	serviceListerSynced    cache.InformerSynced
	secretLister           listers.SecretLister
	secretListerSynced     cache.InformerSynced
	configMapLister        listers.ConfigMapLister
	configMapListerSynced  cache.InformerSynced
	deploymentLister       applisters.DeploymentLister
	deploymentListerSynced cache.InformerSynced

	sharedInformer            informers.SharedInformerFactory
	coreSharedInformer        kubeinformers.SharedInformerFactory
	proxyLister               proxyListers.ProxyLister
	proxyListerSynced         cache.InformerSynced
	backendLister             proxyListers.BackendLister
	backendListerSynced       cache.InformerSynced
	roleLister                proxyListers.RoleLister
	roleListerSynced          cache.InformerSynced
	roleBindingLister         proxyListers.RoleBindingLister
	roleBindingListerSynced   cache.InformerSynced
	rpcPermissionLister       proxyListers.RpcPermissionLister
	rpcPermissionListerSynced cache.InformerSynced

	ecLister       etcdListers.EtcdClusterLister
	ecListerSynced cache.InformerSynced
	pmLister       mListers.PodMonitorLister
	pmListerSynced cache.InformerSynced

	enablePrometheusOperator bool

	queue    workqueue.RateLimitingInterface
	recorder record.EventRecorder

	clientset           clientset.Interface
	monitoringClientset mClientset.Interface
	cmClientset         cmClientset.Interface
}

func NewProxyController(
	ctx context.Context,
	sharedInformerFactory informers.SharedInformerFactory,
	coreSharedInformerFactory kubeinformers.SharedInformerFactory,
	client kubernetes.Interface,
	proxyClient clientset.Interface,
	cmClient cmClientset.Interface,
	mClient mClientset.Interface,
) (*ProxyController, error) {
	proxyInformer := sharedInformerFactory.Proxy().V1().Proxies()
	backendInformer := sharedInformerFactory.Proxy().V1().Backends()
	roleInformer := sharedInformerFactory.Proxy().V1().Roles()
	roleBindingInformer := sharedInformerFactory.Proxy().V1().RoleBindings()
	rpcPermissionInformer := sharedInformerFactory.Proxy().V1().RpcPermissions()
	ecInformer := sharedInformerFactory.Etcd().V1alpha1().EtcdClusters()

	serviceInformer := coreSharedInformerFactory.Core().V1().Services()
	secretInformer := coreSharedInformerFactory.Core().V1().Secrets()
	configMapInformer := coreSharedInformerFactory.Core().V1().ConfigMaps()
	deploymentInformer := coreSharedInformerFactory.Apps().V1().Deployments()

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: client.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "proxy-controller"})

	c := &ProxyController{
		client:                 client,
		serviceLister:          serviceInformer.Lister(),
		serviceListerSynced:    serviceInformer.Informer().HasSynced,
		secretLister:           secretInformer.Lister(),
		secretListerSynced:     secretInformer.Informer().HasSynced,
		configMapLister:        configMapInformer.Lister(),
		configMapListerSynced:  configMapInformer.Informer().HasSynced,
		deploymentLister:       deploymentInformer.Lister(),
		deploymentListerSynced: deploymentInformer.Informer().HasSynced,
		clientset:              proxyClient,
		cmClientset:            cmClient,
		sharedInformer:         sharedInformerFactory,
		coreSharedInformer:     coreSharedInformerFactory,
		queue:                  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Etcd"),
		recorder:               recorder,
	}

	_, apiList, err := client.Discovery().ServerGroupsAndResources()
	if err != nil {
		return nil, err
	}
	if err := c.checkCustomResource(apiList, "cert-manager.io/v1alpha2", "Certificate"); err != nil {
		return nil, err
	}
	c.discoverPrometheusOperator(apiList)

	if c.enablePrometheusOperator {
		mSharedInformer := mInformers.NewSharedInformerFactory(mClient, 30*time.Second)
		c.monitoringClientset = mClient

		pmInformer := mSharedInformer.Monitoring().V1().PodMonitors()
		c.pmLister = pmInformer.Lister()
		c.pmListerSynced = pmInformer.Informer().HasSynced
		mSharedInformer.Start(ctx.Done())
	}

	proxyInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addProxy,
		UpdateFunc: c.updateProxy,
		DeleteFunc: c.deleteProxy,
	})
	c.proxyLister = proxyInformer.Lister()
	c.proxyListerSynced = proxyInformer.Informer().HasSynced

	backendInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addBackend,
		UpdateFunc: c.updateBackend,
		DeleteFunc: c.deleteBackend,
	})
	c.backendLister = backendInformer.Lister()
	c.backendListerSynced = backendInformer.Informer().HasSynced

	roleInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addRole,
		UpdateFunc: c.updateRole,
		DeleteFunc: c.deleteRole,
	})
	c.roleLister = roleInformer.Lister()
	c.roleListerSynced = roleInformer.Informer().HasSynced

	roleBindingInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addRoleBinding,
		UpdateFunc: c.updateRoleBinding,
		DeleteFunc: c.deleteRoleBinding,
	})
	c.roleBindingLister = roleBindingInformer.Lister()
	c.roleBindingListerSynced = roleBindingInformer.Informer().HasSynced

	rpcPermissionInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addRpcPermission,
		UpdateFunc: c.updateRpcPermission,
		DeleteFunc: c.deleteRpcPermission,
	})
	c.rpcPermissionLister = rpcPermissionInformer.Lister()
	c.rpcPermissionListerSynced = rpcPermissionInformer.Informer().HasSynced

	c.ecLister = ecInformer.Lister()
	c.ecListerSynced = ecInformer.Informer().HasSynced

	return c, nil
}

func (c *ProxyController) Run(ctx context.Context, workers int) {
	defer c.queue.ShutDown()

	if !cache.WaitForNamedCacheSync(c.Kind, ctx.Done(),
		c.ecListerSynced,
		c.rpcPermissionListerSynced,
		c.roleListerSynced,
		c.roleBindingListerSynced,
		c.backendListerSynced,
		c.proxyListerSynced,
		c.serviceListerSynced,
		c.secretListerSynced,
		c.configMapListerSynced,
		c.deploymentListerSynced,
	) {
		return
	}
	if c.pmListerSynced != nil && !cache.WaitForNamedCacheSync(c.Kind, ctx.Done(), c.pmListerSynced) {
		return
	}

	for i := 0; i < workers; i++ {
		go wait.Until(c.worker, time.Second, ctx.Done())
	}

	<-ctx.Done()
}

func (c *ProxyController) checkCustomResource(apiList []*metav1.APIResourceList, groupVersion, kind string) error {
	for _, v := range apiList {
		if v.GroupVersion == groupVersion {
			for _, v := range v.APIResources {
				if v.Kind == kind {
					return nil
				}
			}
		}
	}

	return fmt.Errorf("controllers: %s/%s not found", groupVersion, kind)
}

func (c *ProxyController) discoverPrometheusOperator(apiList []*metav1.APIResourceList) {
	for _, v := range apiList {
		if v.GroupVersion == "monitoring.coreos.com/v1" {
			c.enablePrometheusOperator = true
			return
		}
	}
}

func (c *ProxyController) syncProxy(key string) error {
	klog.V(4).Info("syncProxy")

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	proxy, err := c.proxyLister.Proxies(namespace).Get(name)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if proxy.Status.Phase == "" {
		proxy.Status.Phase = proxyv1.ProxyPhaseCreating
		proxy, err = c.clientset.ProxyV1().Proxies(proxy.Namespace).UpdateStatus(proxy)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	selector, err := metav1.LabelSelectorAsSelector(&proxy.Spec.BackendSelector.LabelSelector)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	backends, err := c.backendLister.List(selector)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	selector, err = metav1.LabelSelectorAsSelector(&proxy.Spec.RoleSelector.LabelSelector)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	roles, err := c.roleLister.List(selector)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	selector, err = metav1.LabelSelectorAsSelector(&proxy.Spec.RpcPermissionSelector.LabelSelector)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	rpcPermissions, err := c.clientset.ProxyV1().RpcPermissions("").List(metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	rolesMap := make(map[string]*proxyv1.Role)
	for _, v := range roles {
		rolesMap[fmt.Sprintf("%s/%s", v.Namespace, v.Name)] = v
	}
	bindings, err := c.roleBindingLister.List(labels.Everything())
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	roleBindings := RoleBindings(bindings).Select(func(binding *proxyv1.RoleBinding) bool {
		_, ok := rolesMap[fmt.Sprintf("%s/%s", binding.RoleRef.Namespace, binding.RoleRef.Name)]
		return ok
	})

	lp := NewHeimdallrProxy(HeimdallrProxyParams{
		Spec:              proxy,
		CertManagerClient: c.cmClientset,
		ServiceLister:     c.serviceLister,
		Backends:          backends,
		Roles:             roles,
		RpcPermissions:    rpcPermissions.Items,
		RoleBindings:      roleBindings,
	})
	if ec, err := c.ownedEtcdCluster(lp); err != nil && !apierrors.IsNotFound(err) {
		return xerrors.Errorf(": %w", err)
	} else if ec != nil {
		lp.Datastore = ec
	}

	if err := c.preCheck(lp); err != nil {
		if apierrors.IsNotFound(errors.Unwrap(err)) {
			c.recorder.Eventf(lp.Object, corev1.EventTypeWarning, "InvalidSpec", "Failure pre-check %v", err)
		}
		return xerrors.Errorf(": %w", err)
	}
	if err := c.prepare(lp); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	newP := lp.Object.DeepCopy()
	newP.Status.CASecretName = lp.CASecretName()
	newP.Status.SigningPrivateKeySecretName = lp.PrivateKeySecretName()
	newP.Status.GithubWebhookSecretName = lp.GithubSecretName()
	newP.Status.CookieSecretName = lp.CookieSecretName()
	newP.Status.InternalTokenSecretName = lp.InternalTokenSecretName()

	if !reflect.DeepEqual(newP.Status, lp.Object.Status) {
		_, err := c.clientset.ProxyV1().Proxies(newP.Namespace).UpdateStatus(newP)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	rpcReady, err := c.reconcileRPCServer(lp)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if !rpcReady {
		return xerrors.Errorf(": %w", WrapRetryError(ErrRPCServerIsNotReady))
	}

	if err := c.reconcileProxyProcess(lp); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := c.reconcileDashboard(lp); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := c.finishReconcile(lp); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (c *ProxyController) ownedEtcdCluster(lp *HeimdallrProxy) (*etcdv1alpha1.EtcdCluster, error) {
	return c.ecLister.EtcdClusters(lp.Namespace).Get(lp.EtcdClusterName())
}

func (c *ProxyController) preCheck(lp *HeimdallrProxy) error {
	_, err := c.secretLister.Secrets(lp.Namespace).Get(lp.Spec.IdentityProvider.ClientSecretRef.Name)
	if err != nil && apierrors.IsNotFound(err) {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (c *ProxyController) prepare(lp *HeimdallrProxy) error {
	secrets := lp.Secrets()
	for _, secret := range secrets {
		if secret.Known() {
			continue
		}

		_, err := c.secretLister.Secrets(lp.Namespace).Get(secret.Name)
		if err != nil && apierrors.IsNotFound(err) {
			secret, err := secret.Create()
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}

			_, err = c.client.CoreV1().Secrets(lp.Namespace).Create(secret)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		} else if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if err := c.reconcileEtcdCluster(lp); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (c *ProxyController) reconcileEtcdCluster(lp *HeimdallrProxy) error {
	newC, newPM := lp.EtcdCluster()

	cluster, err := c.ecLister.EtcdClusters(lp.Namespace).Get(lp.EtcdClusterName())
	if err != nil {
		if apierrors.IsNotFound(err) {
			cluster, err = c.clientset.EtcdV1alpha1().EtcdClusters(lp.Namespace).Create(newC)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}

			return WrapRetryError(ErrEtcdClusterIsNotReady)
		}

		return xerrors.Errorf(": %w", err)
	}

	if !cluster.Status.Ready {
		return WrapRetryError(ErrEtcdClusterIsNotReady)
	}

	var podMonitor *monitoringv1.PodMonitor
	if c.enablePrometheusOperator && lp.Spec.Monitor.PrometheusMonitoring {
		podMonitor, err = c.pmLister.PodMonitors(lp.Namespace).Get(newPM.Name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				_, err = c.monitoringClientset.MonitoringV1().PodMonitors(lp.Namespace).Create(newPM)
				if err != nil {
					return xerrors.Errorf(": %w", err)
				}
				return nil
			}

			return xerrors.Errorf(": %w", err)
		}
	}

	if !reflect.DeepEqual(newC.Spec, cluster.Spec) {
		cluster.Spec = newC.Spec
		_, err = c.clientset.EtcdV1alpha1().EtcdClusters(lp.Namespace).Update(cluster)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if podMonitor != nil && newPM != nil {
		if !reflect.DeepEqual(podMonitor.Labels, newPM.Labels) || !reflect.DeepEqual(podMonitor.Spec, newPM.Spec) {
			_, err = c.monitoringClientset.MonitoringV1().PodMonitors(lp.Name).Update(newPM)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}

	return nil
}

func (c *ProxyController) reconcileRPCServer(lp *HeimdallrProxy) (bool, error) {
	objs, err := lp.IdealRPCServer()
	if err != nil {
		return false, xerrors.Errorf(": %w", err)
	}

	if err := c.reconcileProcess(lp, objs); err != nil {
		return false, xerrors.Errorf(": %w", err)
	}
	lp.RPCServer = objs

	if !c.isReadyDeployment(objs.Deployment) {
		return false, nil
	}

	return true, nil
}

func (c *ProxyController) reconcileDashboard(lp *HeimdallrProxy) error {
	objs, err := lp.IdealDashboard()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	err = c.reconcileProcess(lp, objs)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	lp.DashboardServer = objs

	return nil
}

func (c *ProxyController) reconcileProxyProcess(lp *HeimdallrProxy) error {
	_, err := c.secretLister.Secrets(lp.Namespace).Get(lp.Spec.IdentityProvider.ClientSecretRef.Name)
	if err != nil && apierrors.IsNotFound(err) {
		return xerrors.Errorf(": %w", err)
	}

	pcs, err := lp.IdealProxyProcess()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	err = c.reconcileProcess(lp, pcs)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	lp.ProxyServer = pcs

	for _, backend := range lp.Backends() {
		found := false
		for _, v := range backend.Status.DeployedBy {
			if v.Name == lp.Name && v.Namespace == lp.Namespace {
				found = true
				break
			}
		}

		if !found && !backend.CreationTimestamp.IsZero() {
			backend.Status.DeployedBy = append(backend.Status.DeployedBy, &proxyv1.ProxyReference{
				Name:      lp.Name,
				Namespace: lp.Namespace,
				Url:       fmt.Sprintf("https://%s.%s.%s", backend.Name, backend.Spec.Layer, lp.Spec.Domain),
			})

			_, err := c.clientset.ProxyV1().Backends(backend.Namespace).UpdateStatus(backend)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}

	return nil
}

func (c *ProxyController) finishReconcile(lp *HeimdallrProxy) error {
	newP := lp.Object.DeepCopy()
	newP.Status.Ready = c.isReady(lp)
	newP.Status.Phase = proxyv1.ProxyPhaseRunning
	newP.Status.CASecretName = lp.CASecretName()
	newP.Status.SigningPrivateKeySecretName = lp.PrivateKeySecretName()
	newP.Status.GithubWebhookSecretName = lp.GithubSecretName()
	newP.Status.CookieSecretName = lp.CookieSecretName()
	newP.Status.InternalTokenSecretName = lp.InternalTokenSecretName()

	if !reflect.DeepEqual(newP.Status, lp.Object.Status) {
		_, err := c.clientset.ProxyV1().Proxies(newP.Namespace).UpdateStatus(newP)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}
	return nil
}

func (c *ProxyController) isReady(lp *HeimdallrProxy) bool {
	if !c.isReadyDeployment(lp.RPCServer.Deployment) {
		return false
	}
	if !c.isReadyDeployment(lp.ProxyServer.Deployment) {
		return false
	}
	if !c.isReadyDeployment(lp.DashboardServer.Deployment) {
		return false
	}

	return true
}

func (c *ProxyController) isReadyDeployment(d *appsv1.Deployment) bool {
	if d.Status.ReadyReplicas < *d.Spec.Replicas {
		return false
	}

	return true
}

func (c *ProxyController) reconcileProcess(lp *HeimdallrProxy, p *process) error {
	if p.Deployment != nil {
		if err := c.createOrUpdateDeployment(lp, p.Deployment); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if p.PodDisruptionBudget != nil {
		if err := c.createOrUpdatePodDisruptionBudget(lp, p.PodDisruptionBudget); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	for _, svc := range p.Service {
		if svc == nil {
			continue
		}

		if err := c.createOrUpdateService(lp, svc); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	for _, v := range p.ConfigMaps {
		if v == nil {
			continue
		}

		if err := c.createOrUpdateConfigMap(lp, v); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if p.Certificate != nil {
		if err := c.createOrUpdateCertificate(lp, p.Certificate); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if c.enablePrometheusOperator {
		for _, v := range p.ServiceMonitors {
			if v == nil {
				continue
			}

			if err := c.createOrUpdateServiceMonitor(lp, v); err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateDeployment(lp *HeimdallrProxy, deployment *appsv1.Deployment) error {
	d, err := c.deploymentLister.Deployments(deployment.Namespace).Get(deployment.Name)
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(deployment)

		newD, err := c.client.AppsV1().Deployments(deployment.Namespace).Create(deployment)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		deployment.Status = newD.Status
		return nil
	} else if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	newD := d.DeepCopy()
	newD.Spec = deployment.Spec
	if !reflect.DeepEqual(newD.Spec, d.Spec) {
		_, err = c.client.AppsV1().Deployments(newD.Namespace).Update(newD)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}
	deployment.Status = d.Status

	return nil
}

func (c *ProxyController) createOrUpdatePodDisruptionBudget(lp *HeimdallrProxy, pdb *policyv1beta1.PodDisruptionBudget) error {
	p, err := c.client.PolicyV1beta1().PodDisruptionBudgets(pdb.Namespace).Get(pdb.Name, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(pdb)

		_, err = c.client.PolicyV1beta1().PodDisruptionBudgets(pdb.Namespace).Create(pdb)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		return nil
	} else if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	newPDB := p.DeepCopy()
	newPDB.Spec = pdb.Spec
	if !reflect.DeepEqual(newPDB.Spec, pdb.Spec) {
		_, err = c.client.PolicyV1beta1().PodDisruptionBudgets(newPDB.Namespace).Update(newPDB)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateService(lp *HeimdallrProxy, svc *corev1.Service) error {
	s, err := c.serviceLister.Services(svc.Namespace).Get(svc.Name)
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(svc)

		_, err = c.client.CoreV1().Services(svc.Namespace).Create(svc)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		return nil
	} else if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	newS := s.DeepCopy()
	newS.Labels = svc.Labels
	newS.Spec.Selector = svc.Spec.Selector
	newS.Spec.Type = svc.Spec.Type
	newS.Spec.Ports = svc.Spec.Ports
	if !reflect.DeepEqual(newS.Labels, s.Labels) || !reflect.DeepEqual(newS.Spec, s.Spec) {
		_, err = c.client.CoreV1().Services(newS.Namespace).Update(newS)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateConfigMap(lp *HeimdallrProxy, configMap *corev1.ConfigMap) error {
	cm, err := c.configMapLister.ConfigMaps(configMap.Namespace).Get(configMap.Name)
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(configMap)

		_, err = c.client.CoreV1().ConfigMaps(configMap.Namespace).Create(configMap)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		return nil
	} else if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	newCM := cm.DeepCopy()
	newCM.Data = configMap.Data

	if !reflect.DeepEqual(newCM.Data, cm.Data) {
		klog.V(4).Infof("Will update ConfigMap: diff\n%s", cmp.Diff(cm.Data, newCM.Data))
		_, err = c.client.CoreV1().ConfigMaps(newCM.Namespace).Update(newCM)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateCertificate(lp *HeimdallrProxy, certificate *certmanager.Certificate) error {
	crt, err := c.cmClientset.CertmanagerV1alpha2().Certificates(certificate.Namespace).Get(certificate.Name, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(certificate)

		_, err = c.cmClientset.CertmanagerV1alpha2().Certificates(certificate.Namespace).Create(certificate)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		return nil
	} else if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	newCRT := crt.DeepCopy()
	newCRT.Spec = certificate.Spec

	if !reflect.DeepEqual(newCRT.Spec, crt.Spec) {
		_, err = c.cmClientset.CertmanagerV1alpha2().Certificates(newCRT.Namespace).Update(newCRT)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateServiceMonitor(lp *HeimdallrProxy, serviceMonitor *monitoringv1.ServiceMonitor) error {
	sm, err := c.monitoringClientset.MonitoringV1().ServiceMonitors(serviceMonitor.Namespace).Get(serviceMonitor.Name, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(serviceMonitor)

		_, err = c.monitoringClientset.MonitoringV1().ServiceMonitors(serviceMonitor.Namespace).Create(serviceMonitor)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		return nil
	} else if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	newSM := sm.DeepCopy()
	newSM.Labels = serviceMonitor.Labels
	newSM.Spec = serviceMonitor.Spec

	if !reflect.DeepEqual(newSM.Spec, sm.Spec) || !reflect.DeepEqual(newSM.ObjectMeta, sm.ObjectMeta) {
		_, err = c.monitoringClientset.MonitoringV1().ServiceMonitors(newSM.Namespace).Update(newSM)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (c *ProxyController) searchParentProxy(m *metav1.ObjectMeta) ([]*proxyv1.Proxy, error) {
	ret, err := c.proxyLister.List(labels.Everything())
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	targets := make([]*proxyv1.Proxy, 0)
Item:
	for _, v := range ret {
		if m.Labels != nil {
			for k := range v.Spec.BackendSelector.MatchLabels {
				value, ok := m.Labels[k]
				if !ok || v.Spec.BackendSelector.MatchLabels[k] != value {
					continue Item
				}
			}
		}

		targets = append(targets, v)
	}

	return targets, nil
}

func (c *ProxyController) worker() {
	for c.processNextItem() {
	}
}

func (c *ProxyController) processNextItem() bool {
	defer klog.V(4).Info("Finish processNextItem")

	obj, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	klog.V(4).Infof("Get next queue: %s", obj)

	err := func(obj interface{}) error {
		defer c.queue.Done(obj)

		err := c.syncProxy(obj.(string))
		if err != nil {
			if errors.Is(err, &RetryError{}) {
				klog.V(4).Infof("Retrying %v", err)
				c.queue.AddRateLimited(obj)
				return nil
			}

			return err
		}

		c.queue.Forget(obj)
		return nil
	}(obj)
	if err != nil {
		klog.Infof("%+v", err)
		return true
	}

	return true
}

func (c *ProxyController) enqueue(proxy *proxyv1.Proxy) {
	if key, err := cache.MetaNamespaceKeyFunc(proxy); err != nil {
		return
	} else {
		c.queue.Add(key)
	}
}

func (c *ProxyController) enqueueSubordinateResource(m *metav1.ObjectMeta) error {
	ret, err := c.searchParentProxy(m)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	for _, v := range ret {
		c.enqueue(v)
	}

	return nil
}

func (c *ProxyController) enqueueDependentProxy(role *proxyv1.Role) error {
	proxies, err := c.proxyLister.List(labels.Everything())
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	target := make(map[string]*proxyv1.Proxy)
NextProxy:
	for _, proxy := range proxies {
		selector, err := metav1.LabelSelectorAsSelector(&proxy.Spec.RoleSelector.LabelSelector)
		if err != nil {
			continue
		}
		roles, err := c.roleLister.List(selector)
		if err != nil {
			continue
		}

		for _, v := range roles {
			if proxy.Spec.RoleSelector.Namespace != "" && v.Namespace != proxy.Spec.RoleSelector.Namespace {
				continue
			}
			if v.Name == role.Name {
				target[proxy.Name] = proxy
				continue NextProxy
			}
		}
	}

	for _, v := range target {
		c.enqueue(v)
	}
	return nil
}

func (c *ProxyController) addProxy(obj interface{}) {
	proxy := obj.(*proxyv1.Proxy)

	c.enqueue(proxy)
}

func (c *ProxyController) updateProxy(before, after interface{}) {
	beforeProxy := before.(*proxyv1.Proxy)
	afterProxy := after.(*proxyv1.Proxy)

	if beforeProxy.UID != afterProxy.UID {
		if key, err := cache.MetaNamespaceKeyFunc(beforeProxy); err != nil {
			return
		} else {
			c.deleteProxy(cache.DeletedFinalStateUnknown{Key: key, Obj: beforeProxy})
		}
	}

	c.enqueue(afterProxy)
}

func (c *ProxyController) deleteProxy(obj interface{}) {
	proxy, ok := obj.(*proxyv1.Proxy)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		proxy, ok = tombstone.Obj.(*proxyv1.Proxy)
		if !ok {
			return
		}
	}

	c.enqueue(proxy)
}

func (c *ProxyController) addBackend(obj interface{}) {
	backend := obj.(*proxyv1.Backend)

	if err := c.enqueueSubordinateResource(&backend.ObjectMeta); err != nil {
		return
	}
}

func (c *ProxyController) updateBackend(before, after interface{}) {
	beforeBackend := before.(*proxyv1.Backend)
	afterBackend := after.(*proxyv1.Backend)

	if beforeBackend.UID != afterBackend.UID {
		if key, err := cache.MetaNamespaceKeyFunc(beforeBackend); err != nil {
			return
		} else {
			c.deleteBackend(cache.DeletedFinalStateUnknown{Key: key, Obj: beforeBackend})
		}
	}

	if err := c.enqueueSubordinateResource(&afterBackend.ObjectMeta); err != nil {
		return
	}
}

func (c *ProxyController) deleteBackend(obj interface{}) {
	backend, ok := obj.(*proxyv1.Backend)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		backend, ok = tombstone.Obj.(*proxyv1.Backend)
		if !ok {
			return
		}
	}

	if err := c.enqueueSubordinateResource(&backend.ObjectMeta); err != nil {
		return
	}
}

func (c *ProxyController) addRole(obj interface{}) {
	role := obj.(*proxyv1.Role)

	if err := c.enqueueSubordinateResource(&role.ObjectMeta); err != nil {
		return
	}
}

func (c *ProxyController) updateRole(before, after interface{}) {
	beforeRole := before.(*proxyv1.Role)
	afterRole := after.(*proxyv1.Role)

	if beforeRole.UID != afterRole.UID {
		if key, err := cache.MetaNamespaceKeyFunc(beforeRole); err != nil {
			return
		} else {
			c.deleteRole(cache.DeletedFinalStateUnknown{Key: key, Obj: beforeRole})
		}
	}

	if err := c.enqueueSubordinateResource(&afterRole.ObjectMeta); err != nil {
		return
	}
}

func (c *ProxyController) deleteRole(obj interface{}) {
	role, ok := obj.(*proxyv1.Role)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		role, ok = tombstone.Obj.(*proxyv1.Role)
		if !ok {
			return
		}
	}

	if err := c.enqueueSubordinateResource(&role.ObjectMeta); err != nil {
		return
	}
}

func (c *ProxyController) addRoleBinding(obj interface{}) {
	roleBinding := obj.(*proxyv1.RoleBinding)

	role, err := c.roleLister.Roles(roleBinding.RoleRef.Namespace).Get(roleBinding.RoleRef.Name)
	if err != nil {
		return
	}

	if err := c.enqueueDependentProxy(role); err != nil {
		return
	}
}

func (c *ProxyController) updateRoleBinding(before, after interface{}) {
	beforeRoleBinding := before.(*proxyv1.RoleBinding)
	afterRoleBinding := after.(*proxyv1.RoleBinding)

	if beforeRoleBinding.UID != afterRoleBinding.UID {
		if key, err := cache.MetaNamespaceKeyFunc(beforeRoleBinding); err != nil {
			return
		} else {
			c.deleteRole(cache.DeletedFinalStateUnknown{Key: key, Obj: beforeRoleBinding})
		}
	}

	role, err := c.roleLister.Roles(afterRoleBinding.RoleRef.Namespace).Get(afterRoleBinding.RoleRef.Name)
	if err != nil {
		return
	}

	if err := c.enqueueDependentProxy(role); err != nil {
		return
	}
}

func (c *ProxyController) deleteRoleBinding(obj interface{}) {
	roleBinding, ok := obj.(*proxyv1.RoleBinding)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		roleBinding, ok = tombstone.Obj.(*proxyv1.RoleBinding)
		if !ok {
			return
		}
	}

	role, err := c.roleLister.Roles(roleBinding.RoleRef.Namespace).Get(roleBinding.RoleRef.Name)
	if err != nil {
		return
	}

	if err := c.enqueueDependentProxy(role); err != nil {
		return
	}
}

func (c *ProxyController) addRpcPermission(obj interface{}) {
	rpcPermission := obj.(*proxyv1.RpcPermission)

	if err := c.enqueueSubordinateResource(&rpcPermission.ObjectMeta); err != nil {
		return
	}
}

func (c *ProxyController) updateRpcPermission(before, after interface{}) {
	beforeRpcPermission := before.(*proxyv1.RpcPermission)
	afterRpcPermission := after.(*proxyv1.RpcPermission)

	if beforeRpcPermission.UID != afterRpcPermission.UID {
		if key, err := cache.MetaNamespaceKeyFunc(beforeRpcPermission); err != nil {
			return
		} else {
			c.deleteRpcPermission(cache.DeletedFinalStateUnknown{Key: key, Obj: beforeRpcPermission})
		}
	}

	if err := c.enqueueSubordinateResource(&afterRpcPermission.ObjectMeta); err != nil {
		return
	}
}

func (c *ProxyController) deleteRpcPermission(obj interface{}) {
	rpcPermission, ok := obj.(*proxyv1.RpcPermission)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		rpcPermission, ok = tombstone.Obj.(*proxyv1.RpcPermission)
		if !ok {
			return
		}
	}

	if err := c.enqueueSubordinateResource(&rpcPermission.ObjectMeta); err != nil {
		return
	}
}
