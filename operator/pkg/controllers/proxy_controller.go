package controllers

import (
	"context"
	"errors"
	"fmt"
	"reflect"

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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	applisters "k8s.io/client-go/listers/apps/v1"
	listers "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"

	etcdv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha1"
	"go.f110.dev/heimdallr/operator/pkg/api/proxy"
	proxyv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha1"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
	informers "go.f110.dev/heimdallr/operator/pkg/informers/externalversions"
	etcdListers "go.f110.dev/heimdallr/operator/pkg/listers/etcd/v1alpha1"
	mListers "go.f110.dev/heimdallr/operator/pkg/listers/monitoring/v1"
	proxyListers "go.f110.dev/heimdallr/operator/pkg/listers/proxy/v1alpha1"
)

var (
	ErrEtcdClusterIsNotReady = errors.New("EtcdCluster is not ready yet")
	ErrRPCServerIsNotReady   = errors.New("rpc server is not ready")
)

var certManagerGroupVersionOrder = []string{"v1", "v1beta1", "v1alpha3", "v1alpha2"}

type ProxyController struct {
	*Controller

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

	sharedInformer        informers.SharedInformerFactory
	coreSharedInformer    kubeinformers.SharedInformerFactory
	proxyInformer         cache.SharedIndexInformer
	proxyLister           proxyListers.ProxyLister
	backendInformer       cache.SharedIndexInformer
	backendLister         proxyListers.BackendLister
	roleInformer          cache.SharedIndexInformer
	roleLister            proxyListers.RoleLister
	roleBindingInformer   cache.SharedIndexInformer
	roleBindingLister     proxyListers.RoleBindingLister
	rpcPermissionInformer cache.SharedIndexInformer
	rpcPermissionLister   proxyListers.RpcPermissionLister

	ecLister       etcdListers.EtcdClusterLister
	ecListerSynced cache.InformerSynced
	pmLister       mListers.PodMonitorLister
	pmListerSynced cache.InformerSynced

	certManagerVersion       string
	enablePrometheusOperator bool

	clientset clientset.Interface
}

func NewProxyController(
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

	c := &ProxyController{
		client:                 client,
		proxyInformer:          proxyInformer.Informer(),
		proxyLister:            proxyInformer.Lister(),
		backendInformer:        backendInformer.Informer(),
		backendLister:          backendInformer.Lister(),
		roleInformer:           roleInformer.Informer(),
		roleLister:             roleInformer.Lister(),
		roleBindingInformer:    roleBindingInformer.Informer(),
		roleBindingLister:      roleBindingInformer.Lister(),
		rpcPermissionInformer:  rpcPermissionInformer.Informer(),
		rpcPermissionLister:    rpcPermissionInformer.Lister(),
		ecLister:               ecInformer.Lister(),
		ecListerSynced:         ecInformer.Informer().HasSynced,
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
		certManagerVersion:     certManagerGroupVersionOrder[len(certManagerGroupVersionOrder)-1],
	}
	c.Controller = NewController(c, client)

	groups, apiList, err := client.Discovery().ServerGroupsAndResources()
	if err != nil {
		return nil, err
	}
	if cmV, err := c.checkCertManagerVersion(groups); err != nil {
		return nil, err
	} else {
		c.Log().Debug("Found cert-manager.io", zap.String("GroupVersion", cmV))
		c.certManagerVersion = cmV
	}
	c.discoverPrometheusOperator(apiList)

	if c.enablePrometheusOperator {
		pmInformer := sharedInformerFactory.Monitoring().V1().PodMonitors()
		c.pmLister = pmInformer.Lister()
		c.pmListerSynced = pmInformer.Informer().HasSynced
	}

	return c, nil
}

func (c *ProxyController) Name() string {
	return "proxy-controller"
}

func (c *ProxyController) Finalizers() []string {
	return []string{}
}

func (c *ProxyController) ListerSynced() []cache.InformerSynced {
	return []cache.InformerSynced{
		c.ecListerSynced,
		c.rpcPermissionInformer.HasSynced,
		c.roleInformer.HasSynced,
		c.roleBindingInformer.HasSynced,
		c.backendInformer.HasSynced,
		c.proxyInformer.HasSynced,
		c.serviceListerSynced,
		c.secretListerSynced,
		c.configMapListerSynced,
		c.deploymentListerSynced,
		c.ingressListerSynced,
	}
}

func (c *ProxyController) EventSources() []cache.SharedIndexInformer {
	return []cache.SharedIndexInformer{
		c.proxyInformer,
		c.backendInformer,
		c.roleInformer,
		c.roleBindingInformer,
		c.rpcPermissionInformer,
	}
}

func (c *ProxyController) ConvertToKeys() ObjectToKeyConverter {
	return func(obj interface{}) (keys []string, err error) {
		switch obj.(type) {
		case *proxyv1alpha1.Proxy:
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err != nil {
				return nil, err
			}
			return []string{key}, nil
		case *proxyv1alpha1.Backend, *proxyv1alpha1.Role, *proxyv1alpha1.RpcPermission:
			metaObj, err := meta.Accessor(obj)
			if err != nil {
				return nil, err
			}
			return c.subordinateResourceKeys(metaObj)
		case *proxyv1alpha1.RoleBinding:
			roleBinding := obj.(*proxyv1alpha1.RoleBinding)
			role, err := c.roleLister.Roles(roleBinding.RoleRef.Namespace).Get(roleBinding.RoleRef.Name)
			if err != nil {
				return nil, err
			}

			return c.dependentProxyKeys(role)
		default:
			c.Log().Info("Unhandled object type", zap.String("type", reflect.TypeOf(obj).String()))
			return nil, nil
		}
	}
}

func (c *ProxyController) subordinateResourceKeys(m metav1.Object) ([]string, error) {
	ret, err := c.searchParentProxy(m)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	keys := make([]string, len(ret))
	for i := range ret {
		k, err := cache.MetaNamespaceKeyFunc(ret[i])
		if err != nil {
			return nil, err
		}
		keys[i] = k
	}

	return keys, nil
}

func (c *ProxyController) dependentProxyKeys(role *proxyv1alpha1.Role) ([]string, error) {
	proxies, err := c.proxyLister.List(labels.Everything())
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	target := make(map[string]*proxyv1alpha1.Proxy)
NextProxy:
	for _, p := range proxies {
		selector, err := metav1.LabelSelectorAsSelector(&p.Spec.RoleSelector.LabelSelector)
		if err != nil {
			continue
		}
		roles, err := c.roleLister.List(selector)
		if err != nil {
			continue
		}

		for _, v := range roles {
			if p.Spec.RoleSelector.Namespace != "" && v.Namespace != p.Spec.RoleSelector.Namespace {
				continue
			}
			if v.Name == role.Name {
				target[p.Name] = p
				continue NextProxy
			}
		}
	}

	keys := make([]string, 0, len(target))
	for _, v := range target {
		k, err := cache.MetaNamespaceKeyFunc(v)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
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

func (c *ProxyController) GetObject(key string) (interface{}, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	p, err := c.proxyLister.Proxies(namespace).Get(name)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return p, nil
}

func (c *ProxyController) UpdateObject(ctx context.Context, obj interface{}) error {
	p, ok := obj.(*proxyv1alpha1.Proxy)
	if !ok {
		return nil
	}

	_, err := c.clientset.ProxyV1alpha1().Proxies(p.Namespace).Update(ctx, p, metav1.UpdateOptions{})
	return err
}

func (c *ProxyController) Reconcile(ctx context.Context, obj interface{}) error {
	c.Log().Debug("Reconcile Proxy")
	proxy := obj.(*proxyv1alpha1.Proxy)

	if proxy.Status.Phase == "" {
		proxy.Status.Phase = proxyv1alpha1.ProxyPhaseCreating
		updateProxy, err := c.clientset.ProxyV1alpha1().Proxies(proxy.Namespace).UpdateStatus(ctx, proxy, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		proxy = updateProxy
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
			c.EventRecorder().Eventf(lp.Object, corev1.EventTypeWarning, "InvalidSpec", "Failure pre-check %v", err)
		}
		newP := lp.Object.DeepCopy()
		newP.Status.Phase = proxyv1alpha1.ProxyPhaseError
		if !reflect.DeepEqual(newP.Status, lp.Object.Status) {
			_, err := c.clientset.ProxyV1alpha1().Proxies(newP.Namespace).UpdateStatus(ctx, newP, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}

		return xerrors.Errorf(": %w", err)
	}
	if err := c.prepare(ctx, lp); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	newP := lp.Object.DeepCopy()
	newP.Status.CASecretName = lp.CASecretName()
	newP.Status.SigningPrivateKeySecretName = lp.PrivateKeySecretName()
	newP.Status.GithubWebhookSecretName = lp.GithubSecretName()
	newP.Status.CookieSecretName = lp.CookieSecretName()
	newP.Status.InternalTokenSecretName = lp.InternalTokenSecretName()

	if !reflect.DeepEqual(newP.Status, lp.Object.Status) {
		_, err := c.clientset.ProxyV1alpha1().Proxies(newP.Namespace).UpdateStatus(ctx, newP, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	rpcReady, err := c.reconcileRPCServer(ctx, lp)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if !rpcReady {
		return xerrors.Errorf(": %w", WrapRetryError(ErrRPCServerIsNotReady))
	}

	if err := c.reconcileProxyProcess(ctx, lp); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := c.reconcileDashboard(ctx, lp); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := c.finishReconcile(ctx, lp); err != nil {
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

func (c *ProxyController) prepare(ctx context.Context, lp *HeimdallrProxy) error {
	secrets := lp.Secrets()
	for _, secret := range secrets {
		if secret.Known() {
			if err := c.removeOwnerReferenceFromSecret(ctx, lp, secret.Name); err != nil {
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

			_, err = c.client.CoreV1().Secrets(lp.Namespace).Create(ctx, secret, metav1.CreateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		} else if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if err := c.reconcileEtcdCluster(ctx, lp); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (c *ProxyController) removeOwnerReferenceFromSecret(ctx context.Context, lp *HeimdallrProxy, secretName string) error {
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
	_, err = c.client.CoreV1().Secrets(s.Namespace).Update(ctx, s, metav1.UpdateOptions{})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (c *ProxyController) reconcileEtcdCluster(ctx context.Context, lp *HeimdallrProxy) error {
	newC, newPM := lp.EtcdCluster()

	cluster, err := c.ecLister.EtcdClusters(lp.Namespace).Get(lp.EtcdClusterName())
	if err != nil {
		if apierrors.IsNotFound(err) {
			cluster, err = c.clientset.EtcdV1alpha1().EtcdClusters(lp.Namespace).Create(ctx, newC, metav1.CreateOptions{})
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
				_, err = c.clientset.MonitoringV1().PodMonitors(lp.Namespace).Create(ctx, newPM, metav1.CreateOptions{})
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
		_, err = c.clientset.EtcdV1alpha1().EtcdClusters(lp.Namespace).Update(ctx, cluster, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if podMonitor != nil && newPM != nil {
		if !reflect.DeepEqual(podMonitor.Labels, newPM.Labels) || !reflect.DeepEqual(podMonitor.Spec, newPM.Spec) {
			podMonitor.Spec = newPM.Spec
			podMonitor.Labels = newPM.Labels
			_, err = c.clientset.MonitoringV1().PodMonitors(lp.Namespace).Update(ctx, podMonitor, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}

	return nil
}

func (c *ProxyController) reconcileRPCServer(ctx context.Context, lp *HeimdallrProxy) (bool, error) {
	objs, err := lp.IdealRPCServer()
	if err != nil {
		return false, xerrors.Errorf(": %w", err)
	}

	if err := c.reconcileProcess(ctx, lp, objs); err != nil {
		return false, xerrors.Errorf(": %w", err)
	}
	lp.RPCServer = objs

	if !c.isReadyDeployment(objs.Deployment) {
		return false, nil
	}

	return true, nil
}

func (c *ProxyController) reconcileDashboard(ctx context.Context, lp *HeimdallrProxy) error {
	objs, err := lp.IdealDashboard()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	err = c.reconcileProcess(ctx, lp, objs)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	lp.DashboardServer = objs

	return nil
}

func (c *ProxyController) reconcileProxyProcess(ctx context.Context, lp *HeimdallrProxy) error {
	_, err := c.secretLister.Secrets(lp.Namespace).Get(lp.Spec.IdentityProvider.ClientSecretRef.Name)
	if err != nil && apierrors.IsNotFound(err) {
		return xerrors.Errorf(": %w", err)
	}

	pcs, err := lp.IdealProxyProcess()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	err = c.reconcileProcess(ctx, lp, pcs)
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

				_, err = c.clientset.ProxyV1alpha1().Backends(updatedB.Namespace).UpdateStatus(ctx, updatedB, metav1.UpdateOptions{})
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
			c.Log().Warn("Could not parse annotation key which contains Ingress name", zap.Error(err))
			continue
		}
		ingress, err := c.ingressLister.Ingresses(ns).Get(name)
		if err != nil && apierrors.IsNotFound(err) {
			c.Log().Info("Skip updating Ingress")
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
			_, err = c.client.NetworkingV1().Ingresses(updatedI.Namespace).UpdateStatus(ctx, updatedI, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}

	return nil
}

func (c *ProxyController) finishReconcile(ctx context.Context, lp *HeimdallrProxy) error {
	newP := lp.Object.DeepCopy()
	newP.Status.Ready = c.isReady(lp)
	newP.Status.Phase = proxyv1alpha1.ProxyPhaseRunning
	newP.Status.CASecretName = lp.CASecretName()
	newP.Status.SigningPrivateKeySecretName = lp.PrivateKeySecretName()
	newP.Status.GithubWebhookSecretName = lp.GithubSecretName()
	newP.Status.CookieSecretName = lp.CookieSecretName()
	newP.Status.InternalTokenSecretName = lp.InternalTokenSecretName()

	if !reflect.DeepEqual(newP.Status, lp.Object.Status) {
		_, err := c.clientset.ProxyV1alpha1().Proxies(newP.Namespace).UpdateStatus(ctx, newP, metav1.UpdateOptions{})
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

func (c *ProxyController) reconcileProcess(ctx context.Context, lp *HeimdallrProxy, p *process) error {
	if p.Deployment != nil {
		if err := c.createOrUpdateDeployment(ctx, lp, p.Deployment); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if p.PodDisruptionBudget != nil {
		if err := c.createOrUpdatePodDisruptionBudget(ctx, lp, p.PodDisruptionBudget); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	for _, svc := range p.Service {
		if svc == nil {
			continue
		}

		if err := c.createOrUpdateService(ctx, lp, svc); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	for _, v := range p.ConfigMaps {
		if v == nil {
			continue
		}

		if err := c.createOrUpdateConfigMap(ctx, lp, v); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if p.Certificate != nil {
		if err := c.createOrUpdateCertificate(ctx, lp, p.Certificate); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if c.enablePrometheusOperator {
		for _, v := range p.ServiceMonitors {
			if v == nil {
				continue
			}

			if err := c.createOrUpdateServiceMonitor(ctx, lp, v); err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateDeployment(ctx context.Context, lp *HeimdallrProxy, deployment *appsv1.Deployment) error {
	d, err := c.deploymentLister.Deployments(deployment.Namespace).Get(deployment.Name)
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(deployment)

		newD, err := c.client.AppsV1().Deployments(deployment.Namespace).Create(ctx, deployment, metav1.CreateOptions{})
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
		_, err = c.client.AppsV1().Deployments(newD.Namespace).Update(ctx, newD, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}
	deployment.Status = d.Status

	return nil
}

func (c *ProxyController) createOrUpdatePodDisruptionBudget(ctx context.Context, lp *HeimdallrProxy, pdb *policyv1beta1.PodDisruptionBudget) error {
	p, err := c.client.PolicyV1beta1().PodDisruptionBudgets(pdb.Namespace).Get(ctx, pdb.Name, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(pdb)

		_, err = c.client.PolicyV1beta1().PodDisruptionBudgets(pdb.Namespace).Create(ctx, pdb, metav1.CreateOptions{})
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
		_, err = c.client.PolicyV1beta1().PodDisruptionBudgets(newPDB.Namespace).Update(ctx, newPDB, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateService(ctx context.Context, lp *HeimdallrProxy, svc *corev1.Service) error {
	s, err := c.serviceLister.Services(svc.Namespace).Get(svc.Name)
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(svc)

		_, err = c.client.CoreV1().Services(svc.Namespace).Create(ctx, svc, metav1.CreateOptions{})
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
	if !c.equalService(newS, s) {
		_, err = c.client.CoreV1().Services(newS.Namespace).Update(ctx, newS, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateConfigMap(ctx context.Context, lp *HeimdallrProxy, configMap *corev1.ConfigMap) error {
	cm, err := c.configMapLister.ConfigMaps(configMap.Namespace).Get(configMap.Name)
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(configMap)

		_, err = c.client.CoreV1().ConfigMaps(configMap.Namespace).Create(ctx, configMap, metav1.CreateOptions{})
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
		c.Log().Debug("Will update ConfigMap", zap.String("diff", cmp.Diff(cm.Data, newCM.Data)))
		_, err = c.client.CoreV1().ConfigMaps(newCM.Namespace).Update(ctx, newCM, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateCertificate(ctx context.Context, lp *HeimdallrProxy, obj runtime.Object) error {
	switch certificate := obj.(type) {
	case *certmanagerv1alpha2.Certificate:
		crt, err := c.clientset.CertmanagerV1alpha2().Certificates(certificate.Namespace).Get(ctx, certificate.Name, metav1.GetOptions{})
		if err != nil && apierrors.IsNotFound(err) {
			lp.ControlObject(certificate)

			_, err = c.clientset.CertmanagerV1alpha2().Certificates(certificate.Namespace).Create(ctx, certificate, metav1.CreateOptions{})
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
			_, err = c.clientset.CertmanagerV1alpha2().Certificates(newCRT.Namespace).Update(ctx, newCRT, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	case *certmanagerv1alpha3.Certificate:
		crt, err := c.clientset.CertmanagerV1alpha3().Certificates(certificate.Namespace).Get(ctx, certificate.Name, metav1.GetOptions{})
		if err != nil && apierrors.IsNotFound(err) {
			lp.ControlObject(certificate)

			_, err = c.clientset.CertmanagerV1alpha3().Certificates(certificate.Namespace).Create(ctx, certificate, metav1.CreateOptions{})
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
			_, err = c.clientset.CertmanagerV1alpha3().Certificates(newCRT.Namespace).Update(ctx, newCRT, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	case *certmanagerv1beta1.Certificate:
		crt, err := c.clientset.CertmanagerV1beta1().Certificates(certificate.Namespace).Get(ctx, certificate.Name, metav1.GetOptions{})
		if err != nil && apierrors.IsNotFound(err) {
			lp.ControlObject(certificate)

			_, err = c.clientset.CertmanagerV1beta1().Certificates(certificate.Namespace).Create(ctx, certificate, metav1.CreateOptions{})
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
			_, err = c.clientset.CertmanagerV1beta1().Certificates(newCRT.Namespace).Update(ctx, newCRT, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	case *certmanagerv1.Certificate:
		crt, err := c.clientset.CertmanagerV1().Certificates(certificate.Namespace).Get(ctx, certificate.Name, metav1.GetOptions{})
		if err != nil && apierrors.IsNotFound(err) {
			lp.ControlObject(certificate)

			_, err = c.clientset.CertmanagerV1().Certificates(certificate.Namespace).Create(ctx, certificate, metav1.CreateOptions{})
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
			_, err = c.clientset.CertmanagerV1().Certificates(newCRT.Namespace).Update(ctx, newCRT, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateServiceMonitor(ctx context.Context, lp *HeimdallrProxy, serviceMonitor *monitoringv1.ServiceMonitor) error {
	sm, err := c.clientset.MonitoringV1().ServiceMonitors(serviceMonitor.Namespace).Get(ctx, serviceMonitor.Name, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(serviceMonitor)

		_, err = c.clientset.MonitoringV1().ServiceMonitors(serviceMonitor.Namespace).Create(ctx, serviceMonitor, metav1.CreateOptions{})
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
		_, err = c.clientset.MonitoringV1().ServiceMonitors(newSM.Namespace).Update(ctx, newSM, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (c *ProxyController) searchParentProxy(m metav1.Object) ([]*proxyv1alpha1.Proxy, error) {
	ret, err := c.proxyLister.List(labels.Everything())
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	targets := make([]*proxyv1alpha1.Proxy, 0)
Item:
	for _, v := range ret {
		if m.GetLabels() != nil {
			for k := range v.Spec.BackendSelector.MatchLabels {
				value, ok := m.GetLabels()[k]
				if !ok || v.Spec.BackendSelector.MatchLabels[k] != value {
					continue Item
				}
			}
		}

		targets = append(targets, v)
	}

	return targets, nil
}

func (c *ProxyController) equalService(left, right *corev1.Service) bool {
	return reflect.DeepEqual(left.Labels, right.Labels) &&
		reflect.DeepEqual(left.Spec.Selector, right.Spec.Selector) &&
		left.Spec.Type == right.Spec.Type &&
		c.equalServicePort(left.Spec.Ports, right.Spec.Ports)
}

func (c *ProxyController) equalServicePort(left, right []corev1.ServicePort) bool {
	l := servicePortMap(left)
	r := servicePortMap(right)
	if len(l) != len(r) {
		return false
	}
	for key := range l {
		if _, ok := r[key]; !ok {
			return false
		}
		if l[key].Protocol != r[key].Protocol {
			return false
		}
		leftTP := l[key].TargetPort
		rightTP := r[key].TargetPort
		if leftTP.IntValue() != rightTP.IntValue() {
			return false
		}
		if l[key].Port != r[key].Port {
			return false
		}
	}

	return true
}

func servicePortMap(ports []corev1.ServicePort) map[string]corev1.ServicePort {
	result := make(map[string]corev1.ServicePort)
	for _, v := range ports {
		result[v.Name] = v
	}

	return result
}
