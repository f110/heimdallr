package controllers

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	monitoringv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/google/go-cmp/cmp"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	certmanagerv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	certmanagerv1alpha2 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	certmanagerv1alpha3 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha3"
	certmanagerv1beta1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1beta1"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	applisters "k8s.io/client-go/listers/apps/v1"
	listers "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"

	etcdv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha1"
	"go.f110.dev/heimdallr/operator/pkg/api/proxy"
	proxyv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha1"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
	"go.f110.dev/heimdallr/operator/pkg/client/versioned/scheme"
	informers "go.f110.dev/heimdallr/operator/pkg/informers/externalversions"
	etcdListers "go.f110.dev/heimdallr/operator/pkg/listers/etcd/v1alpha1"
	mListers "go.f110.dev/heimdallr/operator/pkg/listers/monitoring/v1"
	proxyListers "go.f110.dev/heimdallr/operator/pkg/listers/proxy/v1alpha1"
	"go.f110.dev/heimdallr/pkg/logger"
)

var (
	ErrEtcdClusterIsNotReady = errors.New("EtcdCluster is not ready yet")
	ErrRPCServerIsNotReady   = errors.New("rpc server is not ready")
)

var certManagerGroupVersionOrder = []string{"v1", "v1beta1", "v1alpha3", "v1alpha2"}

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
	ingressLister          networkinglisters.IngressLister
	ingressListerSynced    cache.InformerSynced

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

	certManagerVersion       string
	enablePrometheusOperator bool

	queue    workqueue.RateLimitingInterface
	recorder record.EventRecorder
	log      *zap.Logger

	clientset clientset.Interface
}

func NewProxyController(
	ctx context.Context,
	sharedInformerFactory informers.SharedInformerFactory,
	coreSharedInformerFactory kubeinformers.SharedInformerFactory,
	client kubernetes.Interface,
	proxyClient clientset.Interface,
) (*ProxyController, error) {
	proxyInformer := sharedInformerFactory.Proxy().V1alpha1().Proxies()
	backendInformer := sharedInformerFactory.Proxy().V1alpha1().Backends()
	roleInformer := sharedInformerFactory.Proxy().V1alpha1().Roles()
	roleBindingInformer := sharedInformerFactory.Proxy().V1alpha1().RoleBindings()
	rpcPermissionInformer := sharedInformerFactory.Proxy().V1alpha1().RpcPermissions()
	ecInformer := sharedInformerFactory.Etcd().V1alpha1().EtcdClusters()

	serviceInformer := coreSharedInformerFactory.Core().V1().Services()
	secretInformer := coreSharedInformerFactory.Core().V1().Secrets()
	configMapInformer := coreSharedInformerFactory.Core().V1().ConfigMaps()
	deploymentInformer := coreSharedInformerFactory.Apps().V1().Deployments()
	ingressInformer := coreSharedInformerFactory.Networking().V1().Ingresses()

	log := logger.Log.Named("proxy-controller")
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(func(format string, args ...interface{}) {
		log.Info(fmt.Sprintf(format, args...))
	})
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
		ingressLister:          ingressInformer.Lister(),
		ingressListerSynced:    ingressInformer.Informer().HasSynced,
		clientset:              proxyClient,
		sharedInformer:         sharedInformerFactory,
		coreSharedInformer:     coreSharedInformerFactory,
		queue:                  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Etcd"),
		recorder:               recorder,
		log:                    log,
		certManagerVersion:     certManagerGroupVersionOrder[len(certManagerGroupVersionOrder)-1],
	}

	groups, apiList, err := client.Discovery().ServerGroupsAndResources()
	if err != nil {
		return nil, err
	}
	if cmV, err := c.checkCertManagerVersion(groups); err != nil {
		return nil, err
	} else {
		logger.Log.Debug("Found cert-manager.io", zap.String("GroupVersion", cmV))
		c.certManagerVersion = cmV
	}
	c.discoverPrometheusOperator(apiList)

	if c.enablePrometheusOperator {
		pmInformer := sharedInformerFactory.Monitoring().V1().PodMonitors()
		c.pmLister = pmInformer.Lister()
		c.pmListerSynced = pmInformer.Informer().HasSynced
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
		c.ingressListerSynced,
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

func (c *ProxyController) checkCertManagerVersion(groups []*metav1.APIGroup) (string, error) {
	for _, v := range groups {
		if v.Name == certmanager.GroupName {
			m := make(map[string]struct{})
			for _, gv := range v.Versions {
				m[gv.Version] = struct{}{}
			}

			for _, k := range certManagerGroupVersionOrder {
				if _, ok := m[k]; ok {
					return k, nil
				}
			}
		}
	}

	return "", fmt.Errorf("controllers: cert-manager.io or compatible GroupVersion not found")
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
	c.log.Debug("syncProxy", zap.String("key", key))

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	proxy, err := c.proxyLister.Proxies(namespace).Get(name)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if proxy.Status.Phase == "" {
		proxy.Status.Phase = proxyv1alpha1.ProxyPhaseCreating
		proxy, err = c.clientset.ProxyV1alpha1().Proxies(proxy.Namespace).UpdateStatus(context.TODO(), proxy, metav1.UpdateOptions{})
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
	rpcPermissions, err := c.rpcPermissionLister.List(selector)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	rolesMap := make(map[string]*proxyv1alpha1.Role)
	for _, v := range roles {
		rolesMap[fmt.Sprintf("%s/%s", v.Namespace, v.Name)] = v
	}
	bindings, err := c.roleBindingLister.List(labels.Everything())
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	roleBindings := RoleBindings(bindings).Select(func(binding *proxyv1alpha1.RoleBinding) bool {
		_, ok := rolesMap[fmt.Sprintf("%s/%s", binding.RoleRef.Namespace, binding.RoleRef.Name)]
		return ok
	})

	lp := NewHeimdallrProxy(HeimdallrProxyParams{
		Spec:               proxy,
		Clientset:          c.clientset,
		ServiceLister:      c.serviceLister,
		Backends:           backends,
		Roles:              roles,
		RpcPermissions:     rpcPermissions,
		RoleBindings:       roleBindings,
		CertManagerVersion: c.certManagerVersion,
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
		newP := lp.Object.DeepCopy()
		newP.Status.Phase = proxyv1alpha1.ProxyPhaseError
		if !reflect.DeepEqual(newP.Status, lp.Object.Status) {
			_, err := c.clientset.ProxyV1alpha1().Proxies(newP.Namespace).UpdateStatus(context.TODO(), newP, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
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
		_, err := c.clientset.ProxyV1alpha1().Proxies(newP.Namespace).UpdateStatus(context.TODO(), newP, metav1.UpdateOptions{})
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
			if err := c.removeOwnerReferenceFromSecret(lp, secret.Name); err != nil {
				return xerrors.Errorf(": %w", err)
			}

			continue
		}

		_, err := c.secretLister.Secrets(lp.Namespace).Get(secret.Name)
		if err != nil && apierrors.IsNotFound(err) {
			secret, err := secret.Create()
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}

			_, err = c.client.CoreV1().Secrets(lp.Namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
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

func (c *ProxyController) removeOwnerReferenceFromSecret(lp *HeimdallrProxy, secretName string) error {
	if lp.Object.UID == "" {
		return nil
	}

	s, err := c.secretLister.Secrets(lp.Namespace).Get(secretName)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	found := false
	newRef := make([]metav1.OwnerReference, 0)
	for _, v := range s.OwnerReferences {
		if v.UID == lp.Object.UID {
			found = true
			continue
		}

		newRef = append(newRef, v)
	}
	if !found {
		return nil
	}
	s.SetOwnerReferences(newRef)
	_, err = c.client.CoreV1().Secrets(s.Namespace).Update(context.TODO(), s, metav1.UpdateOptions{})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (c *ProxyController) reconcileEtcdCluster(lp *HeimdallrProxy) error {
	newC, newPM := lp.EtcdCluster()

	cluster, err := c.ecLister.EtcdClusters(lp.Namespace).Get(lp.EtcdClusterName())
	if err != nil {
		if apierrors.IsNotFound(err) {
			cluster, err = c.clientset.EtcdV1alpha1().EtcdClusters(lp.Namespace).Create(context.TODO(), newC, metav1.CreateOptions{})
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
				_, err = c.clientset.MonitoringV1().PodMonitors(lp.Namespace).Create(context.TODO(), newPM, metav1.CreateOptions{})
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
		_, err = c.clientset.EtcdV1alpha1().EtcdClusters(lp.Namespace).Update(context.TODO(), cluster, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if podMonitor != nil && newPM != nil {
		if !reflect.DeepEqual(podMonitor.Labels, newPM.Labels) || !reflect.DeepEqual(podMonitor.Spec, newPM.Spec) {
			podMonitor.Spec = newPM.Spec
			podMonitor.Labels = newPM.Labels
			_, err = c.clientset.MonitoringV1().PodMonitors(lp.Namespace).Update(context.TODO(), podMonitor, metav1.UpdateOptions{})
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

		hostname := fmt.Sprintf("%s.%s.%s", backend.Name, backend.Spec.Layer, lp.Spec.Domain)
		if backend.Spec.FQDN != "" {
			hostname = backend.Spec.FQDN
		}
		if !found && !backend.CreationTimestamp.IsZero() {
			err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				updatedB, err := c.backendLister.Backends(backend.Namespace).Get(backend.Name)
				if err != nil {
					return err
				}

				updatedB.Status.DeployedBy = append(updatedB.Status.DeployedBy, &proxyv1alpha1.ProxyReference{
					Name:      lp.Name,
					Namespace: lp.Namespace,
					Url:       fmt.Sprintf("https://%s", hostname),
				})

				_, err = c.clientset.ProxyV1alpha1().Backends(updatedB.Namespace).UpdateStatus(context.TODO(), updatedB, metav1.UpdateOptions{})
				return err
			})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}

		if _, ok := backend.Annotations[proxy.AnnotationKeyIngressName]; !ok {
			continue
		}
		ns, name, err := cache.SplitMetaNamespaceKey(backend.Annotations[proxy.AnnotationKeyIngressName])
		if err != nil {
			c.log.Warn("Could not parse annotation key which contains Ingress name", zap.Error(err))
			continue
		}
		ingress, err := c.ingressLister.Ingresses(ns).Get(name)
		if err != nil && apierrors.IsNotFound(err) {
			c.log.Info("Skip updating Ingress")
			continue
		} else if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		updatedI := ingress.DeepCopy()
		found = false
		for _, v := range ingress.Status.LoadBalancer.Ingress {
			if v.Hostname == hostname {
				found = true
			}
		}
		if found {
			continue
		}
		updatedI.Status.LoadBalancer.Ingress = append(updatedI.Status.LoadBalancer.Ingress, corev1.LoadBalancerIngress{
			Hostname: hostname,
		})
		if !reflect.DeepEqual(updatedI.Status, ingress.Status) {
			_, err = c.client.NetworkingV1().Ingresses(updatedI.Namespace).UpdateStatus(context.TODO(), updatedI, metav1.UpdateOptions{})
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
	newP.Status.Phase = proxyv1alpha1.ProxyPhaseRunning
	newP.Status.CASecretName = lp.CASecretName()
	newP.Status.SigningPrivateKeySecretName = lp.PrivateKeySecretName()
	newP.Status.GithubWebhookSecretName = lp.GithubSecretName()
	newP.Status.CookieSecretName = lp.CookieSecretName()
	newP.Status.InternalTokenSecretName = lp.InternalTokenSecretName()

	if !reflect.DeepEqual(newP.Status, lp.Object.Status) {
		_, err := c.clientset.ProxyV1alpha1().Proxies(newP.Namespace).UpdateStatus(context.TODO(), newP, metav1.UpdateOptions{})
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

		newD, err := c.client.AppsV1().Deployments(deployment.Namespace).Create(context.TODO(), deployment, metav1.CreateOptions{})
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
		_, err = c.client.AppsV1().Deployments(newD.Namespace).Update(context.TODO(), newD, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}
	deployment.Status = d.Status

	return nil
}

func (c *ProxyController) createOrUpdatePodDisruptionBudget(lp *HeimdallrProxy, pdb *policyv1beta1.PodDisruptionBudget) error {
	p, err := c.client.PolicyV1beta1().PodDisruptionBudgets(pdb.Namespace).Get(context.TODO(), pdb.Name, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(pdb)

		_, err = c.client.PolicyV1beta1().PodDisruptionBudgets(pdb.Namespace).Create(context.TODO(), pdb, metav1.CreateOptions{})
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
		_, err = c.client.PolicyV1beta1().PodDisruptionBudgets(newPDB.Namespace).Update(context.TODO(), newPDB, metav1.UpdateOptions{})
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

		_, err = c.client.CoreV1().Services(svc.Namespace).Create(context.TODO(), svc, metav1.CreateOptions{})
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
		_, err = c.client.CoreV1().Services(newS.Namespace).Update(context.TODO(), newS, metav1.UpdateOptions{})
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

		_, err = c.client.CoreV1().ConfigMaps(configMap.Namespace).Create(context.TODO(), configMap, metav1.CreateOptions{})
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
		c.log.Debug("Will update ConfigMap", zap.String("diff", cmp.Diff(cm.Data, newCM.Data)))
		_, err = c.client.CoreV1().ConfigMaps(newCM.Namespace).Update(context.TODO(), newCM, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateCertificate(lp *HeimdallrProxy, obj runtime.Object) error {
	switch certificate := obj.(type) {
	case *certmanagerv1alpha2.Certificate:
		crt, err := c.clientset.CertmanagerV1alpha2().Certificates(certificate.Namespace).Get(context.TODO(), certificate.Name, metav1.GetOptions{})
		if err != nil && apierrors.IsNotFound(err) {
			lp.ControlObject(certificate)

			_, err = c.clientset.CertmanagerV1alpha2().Certificates(certificate.Namespace).Create(context.TODO(), certificate, metav1.CreateOptions{})
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
			_, err = c.clientset.CertmanagerV1alpha2().Certificates(newCRT.Namespace).Update(context.TODO(), newCRT, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	case *certmanagerv1alpha3.Certificate:
		crt, err := c.clientset.CertmanagerV1alpha3().Certificates(certificate.Namespace).Get(context.TODO(), certificate.Name, metav1.GetOptions{})
		if err != nil && apierrors.IsNotFound(err) {
			lp.ControlObject(certificate)

			_, err = c.clientset.CertmanagerV1alpha3().Certificates(certificate.Namespace).Create(context.TODO(), certificate, metav1.CreateOptions{})
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
			_, err = c.clientset.CertmanagerV1alpha3().Certificates(newCRT.Namespace).Update(context.TODO(), newCRT, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	case *certmanagerv1beta1.Certificate:
		crt, err := c.clientset.CertmanagerV1beta1().Certificates(certificate.Namespace).Get(context.TODO(), certificate.Name, metav1.GetOptions{})
		if err != nil && apierrors.IsNotFound(err) {
			lp.ControlObject(certificate)

			_, err = c.clientset.CertmanagerV1beta1().Certificates(certificate.Namespace).Create(context.TODO(), certificate, metav1.CreateOptions{})
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
			_, err = c.clientset.CertmanagerV1beta1().Certificates(newCRT.Namespace).Update(context.TODO(), newCRT, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	case *certmanagerv1.Certificate:
		crt, err := c.clientset.CertmanagerV1().Certificates(certificate.Namespace).Get(context.TODO(), certificate.Name, metav1.GetOptions{})
		if err != nil && apierrors.IsNotFound(err) {
			lp.ControlObject(certificate)

			_, err = c.clientset.CertmanagerV1().Certificates(certificate.Namespace).Create(context.TODO(), certificate, metav1.CreateOptions{})
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
			_, err = c.clientset.CertmanagerV1().Certificates(newCRT.Namespace).Update(context.TODO(), newCRT, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateServiceMonitor(lp *HeimdallrProxy, serviceMonitor *monitoringv1.ServiceMonitor) error {
	sm, err := c.clientset.MonitoringV1().ServiceMonitors(serviceMonitor.Namespace).Get(context.TODO(), serviceMonitor.Name, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(serviceMonitor)

		_, err = c.clientset.MonitoringV1().ServiceMonitors(serviceMonitor.Namespace).Create(context.TODO(), serviceMonitor, metav1.CreateOptions{})
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
		_, err = c.clientset.MonitoringV1().ServiceMonitors(newSM.Namespace).Update(context.TODO(), newSM, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (c *ProxyController) searchParentProxy(m *metav1.ObjectMeta) ([]*proxyv1alpha1.Proxy, error) {
	ret, err := c.proxyLister.List(labels.Everything())
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	targets := make([]*proxyv1alpha1.Proxy, 0)
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
	defer c.log.Debug("Finish processNextItem")

	obj, shutdown := c.queue.Get()
	if shutdown {
		return false
	}
	c.log.Debug("Get next queue", zap.Any("key", obj))

	err := func(obj interface{}) error {
		defer c.queue.Done(obj)

		err := c.syncProxy(obj.(string))
		if err != nil {
			if errors.Is(err, &RetryError{}) {
				c.log.Debug("Retrying", zap.Error(err))
				c.queue.AddRateLimited(obj)
				return nil
			}

			return err
		}

		c.queue.Forget(obj)
		return nil
	}(obj)
	if err != nil {
		c.log.Info("Failed sync", zap.Error(err))
		return true
	}

	return true
}

func (c *ProxyController) enqueue(proxy *proxyv1alpha1.Proxy) {
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

func (c *ProxyController) enqueueDependentProxy(role *proxyv1alpha1.Role) error {
	proxies, err := c.proxyLister.List(labels.Everything())
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	target := make(map[string]*proxyv1alpha1.Proxy)
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
	proxy := obj.(*proxyv1alpha1.Proxy)

	c.enqueue(proxy)
}

func (c *ProxyController) updateProxy(before, after interface{}) {
	beforeProxy := before.(*proxyv1alpha1.Proxy)
	afterProxy := after.(*proxyv1alpha1.Proxy)

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
	proxy, ok := obj.(*proxyv1alpha1.Proxy)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		proxy, ok = tombstone.Obj.(*proxyv1alpha1.Proxy)
		if !ok {
			return
		}
	}

	c.enqueue(proxy)
}

func (c *ProxyController) addBackend(obj interface{}) {
	backend := obj.(*proxyv1alpha1.Backend)

	if err := c.enqueueSubordinateResource(&backend.ObjectMeta); err != nil {
		return
	}
}

func (c *ProxyController) updateBackend(before, after interface{}) {
	beforeBackend := before.(*proxyv1alpha1.Backend)
	afterBackend := after.(*proxyv1alpha1.Backend)

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
	backend, ok := obj.(*proxyv1alpha1.Backend)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		backend, ok = tombstone.Obj.(*proxyv1alpha1.Backend)
		if !ok {
			return
		}
	}

	if err := c.enqueueSubordinateResource(&backend.ObjectMeta); err != nil {
		return
	}
}

func (c *ProxyController) addRole(obj interface{}) {
	role := obj.(*proxyv1alpha1.Role)

	if err := c.enqueueSubordinateResource(&role.ObjectMeta); err != nil {
		return
	}
}

func (c *ProxyController) updateRole(before, after interface{}) {
	beforeRole := before.(*proxyv1alpha1.Role)
	afterRole := after.(*proxyv1alpha1.Role)

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
	role, ok := obj.(*proxyv1alpha1.Role)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		role, ok = tombstone.Obj.(*proxyv1alpha1.Role)
		if !ok {
			return
		}
	}

	if err := c.enqueueSubordinateResource(&role.ObjectMeta); err != nil {
		return
	}
}

func (c *ProxyController) addRoleBinding(obj interface{}) {
	roleBinding := obj.(*proxyv1alpha1.RoleBinding)

	role, err := c.roleLister.Roles(roleBinding.RoleRef.Namespace).Get(roleBinding.RoleRef.Name)
	if err != nil {
		return
	}

	if err := c.enqueueDependentProxy(role); err != nil {
		return
	}
}

func (c *ProxyController) updateRoleBinding(before, after interface{}) {
	beforeRoleBinding := before.(*proxyv1alpha1.RoleBinding)
	afterRoleBinding := after.(*proxyv1alpha1.RoleBinding)

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
	roleBinding, ok := obj.(*proxyv1alpha1.RoleBinding)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		roleBinding, ok = tombstone.Obj.(*proxyv1alpha1.RoleBinding)
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
	rpcPermission := obj.(*proxyv1alpha1.RpcPermission)

	if err := c.enqueueSubordinateResource(&rpcPermission.ObjectMeta); err != nil {
		return
	}
}

func (c *ProxyController) updateRpcPermission(before, after interface{}) {
	beforeRpcPermission := before.(*proxyv1alpha1.RpcPermission)
	afterRpcPermission := after.(*proxyv1alpha1.RpcPermission)

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
	rpcPermission, ok := obj.(*proxyv1alpha1.RpcPermission)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		rpcPermission, ok = tombstone.Obj.(*proxyv1alpha1.RpcPermission)
		if !ok {
			return
		}
	}

	if err := c.enqueueSubordinateResource(&rpcPermission.ObjectMeta); err != nil {
		return
	}
}
