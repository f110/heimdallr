package controllers

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager"
	"go.f110.dev/kubeproto/go/apis/appsv1"
	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"
	"go.f110.dev/kubeproto/go/apis/networkingv1"
	"go.f110.dev/kubeproto/go/apis/policyv1"
	"go.f110.dev/kubeproto/go/k8sclient"
	"go.f110.dev/xerrors"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"

	"go.f110.dev/heimdallr/pkg/k8s/api/etcdv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxy"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxyv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/client"
	"go.f110.dev/heimdallr/pkg/k8s/controllers/controllerbase"
	"go.f110.dev/heimdallr/pkg/k8s/thirdpartyapi/cert-manager/certmanagerv1"
	"go.f110.dev/heimdallr/pkg/k8s/thirdpartyapi/prometheus-operator/monitoringv1"
	"go.f110.dev/heimdallr/pkg/k8s/thirdpartyclient"
)

var (
	ErrEtcdClusterIsNotReady = xerrors.New("EtcdCluster is not ready yet")
	ErrRPCServerIsNotReady   = xerrors.New("rpc server is not ready")
)

var certManagerGroupVersionOrder = []string{"v1", "v1beta1", "v1alpha3", "v1alpha2"}

type ProxyController struct {
	*controllerbase.Controller

	client                 *k8sclient.Set
	serviceLister          *k8sclient.CoreV1ServiceLister
	serviceListerSynced    cache.InformerSynced
	secretLister           *k8sclient.CoreV1SecretLister
	secretListerSynced     cache.InformerSynced
	configMapLister        *k8sclient.CoreV1ConfigMapLister
	configMapListerSynced  cache.InformerSynced
	deploymentLister       *k8sclient.AppsV1DeploymentLister
	deploymentListerSynced cache.InformerSynced
	ingressLister          *k8sclient.NetworkingK8sIoV1IngressLister
	ingressListerSynced    cache.InformerSynced

	coreSharedInformer    *k8sclient.InformerFactory
	proxyInformer         cache.SharedIndexInformer
	proxyLister           *client.ProxyV1alpha2ProxyLister
	backendInformer       cache.SharedIndexInformer
	backendLister         *client.ProxyV1alpha2BackendLister
	roleInformer          cache.SharedIndexInformer
	roleLister            *client.ProxyV1alpha2RoleLister
	roleBindingInformer   cache.SharedIndexInformer
	roleBindingLister     *client.ProxyV1alpha2RoleBindingLister
	rpcPermissionInformer cache.SharedIndexInformer
	rpcPermissionLister   *client.ProxyV1alpha2RpcPermissionLister

	ecLister       *client.EtcdV1alpha2EtcdClusterLister
	ecListerSynced cache.InformerSynced
	pmLister       *thirdpartyclient.CoreosComV1PodMonitorLister
	pmListerSynced cache.InformerSynced

	certManagerVersion       string
	enablePrometheusOperator bool

	clientset           *client.Set
	thirdPartyClientSet *thirdpartyclient.Set
}

func NewProxyController(
	ctx context.Context,
	sharedInformerFactory *client.InformerFactory,
	coreSharedInformerFactory *k8sclient.InformerFactory,
	coreClient *k8sclient.Set,
	clientSet *client.Set,
	thirdPartyClientSet *thirdpartyclient.Set,
	k8sClient kubernetes.Interface,
) (*ProxyController, error) {
	proxyInformer := client.NewProxyV1alpha2Informer(sharedInformerFactory.Cache(), clientSet.ProxyV1alpha2, metav1.NamespaceAll, 30*time.Second)
	ecInformer := client.NewEtcdV1alpha2Informer(sharedInformerFactory.Cache(), clientSet.EtcdV1alpha2, metav1.NamespaceAll, 30*time.Second)

	corev1Informer := k8sclient.NewCoreV1Informer(coreSharedInformerFactory.Cache(), coreClient.CoreV1, metav1.NamespaceAll, 30*time.Second)
	networkingv1Informer := k8sclient.NewNetworkingK8sIoV1Informer(coreSharedInformerFactory.Cache(), coreClient.NetworkingK8sIoV1, metav1.NamespaceAll, 30*time.Second)
	appsv1Informer := k8sclient.NewAppsV1Informer(coreSharedInformerFactory.Cache(), coreClient.AppsV1, metav1.NamespaceAll, 30*time.Second)

	c := &ProxyController{
		client:                 coreClient,
		proxyInformer:          proxyInformer.ProxyInformer(),
		proxyLister:            proxyInformer.ProxyLister(),
		backendInformer:        proxyInformer.BackendInformer(),
		backendLister:          proxyInformer.BackendLister(),
		roleInformer:           proxyInformer.RoleInformer(),
		roleLister:             proxyInformer.RoleLister(),
		roleBindingInformer:    proxyInformer.RoleBindingInformer(),
		roleBindingLister:      proxyInformer.RoleBindingLister(),
		rpcPermissionInformer:  proxyInformer.RpcPermissionInformer(),
		rpcPermissionLister:    proxyInformer.RpcPermissionLister(),
		ecLister:               ecInformer.EtcdClusterLister(),
		ecListerSynced:         ecInformer.EtcdClusterInformer().HasSynced,
		serviceLister:          corev1Informer.ServiceLister(),
		serviceListerSynced:    corev1Informer.ServiceInformer().HasSynced,
		secretLister:           corev1Informer.SecretLister(),
		secretListerSynced:     corev1Informer.SecretInformer().HasSynced,
		configMapLister:        corev1Informer.ConfigMapLister(),
		configMapListerSynced:  corev1Informer.ConfigMapInformer().HasSynced,
		deploymentLister:       appsv1Informer.DeploymentLister(),
		deploymentListerSynced: appsv1Informer.DeploymentInformer().HasSynced,
		ingressLister:          networkingv1Informer.IngressLister(),
		ingressListerSynced:    networkingv1Informer.IngressInformer().HasSynced,
		clientset:              clientSet,
		thirdPartyClientSet:    thirdPartyClientSet,
		coreSharedInformer:     coreSharedInformerFactory,
		certManagerVersion:     certManagerGroupVersionOrder[len(certManagerGroupVersionOrder)-1],
	}
	c.Controller = controllerbase.NewController(c, k8sClient)

	groups, apiList, err := k8sClient.Discovery().ServerGroupsAndResources()
	if err != nil {
		return nil, err
	}
	if cmV, err := c.checkCertManagerVersion(groups); err != nil {
		return nil, err
	} else {
		c.Log(nil).Debug("Found cert-manager.io", zap.String("GroupVersion", cmV))
		c.certManagerVersion = cmV
	}
	c.discoverPrometheusOperator(apiList)

	if c.enablePrometheusOperator {
		f := thirdpartyclient.NewInformerFactory(thirdPartyClientSet, thirdpartyclient.NewInformerCache(), metav1.NamespaceAll, 30*time.Second)
		coreosInformer := thirdpartyclient.NewCoreosComV1Informer(f.Cache(), thirdPartyClientSet.CoreosComV1, metav1.NamespaceAll, 30*time.Second)
		c.pmLister = coreosInformer.PodMonitorLister()
		c.pmListerSynced = coreosInformer.PodMonitorInformer().HasSynced
		f.Run(ctx)
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

func (c *ProxyController) ConvertToKeys() controllerbase.ObjectToKeyConverter {
	return func(obj interface{}) (keys []string, err error) {
		switch obj.(type) {
		case *proxyv1alpha2.Proxy:
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err != nil {
				return nil, err
			}
			return []string{key}, nil
		case *proxyv1alpha2.Backend, *proxyv1alpha2.Role, *proxyv1alpha2.RpcPermission:
			metaObj := obj.(metav1.Object)
			return c.subordinateResourceKeys(metaObj)
		case *proxyv1alpha2.RoleBinding:
			roleBinding := obj.(*proxyv1alpha2.RoleBinding)
			role, err := c.roleLister.Get(roleBinding.RoleRef.Namespace, roleBinding.RoleRef.Name)
			if err != nil {
				return nil, err
			}

			return c.dependentProxyKeys(role)
		default:
			c.Log(nil).Info("Unhandled object type", zap.String("type", reflect.TypeOf(obj).String()))
			return nil, nil
		}
	}
}

func (c *ProxyController) subordinateResourceKeys(m metav1.Object) ([]string, error) {
	ret, err := c.searchParentProxy(m)
	if err != nil {
		return nil, err
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

func (c *ProxyController) dependentProxyKeys(role *proxyv1alpha2.Role) ([]string, error) {
	proxies, err := c.proxyLister.List(metav1.NamespaceAll, labels.Everything())
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	target := make(map[string]*proxyv1alpha2.Proxy)
NextProxy:
	for _, p := range proxies {
		selector, err := metav1.LabelSelectorAsSelector(&p.Spec.RoleSelector.LabelSelector)
		if err != nil {
			continue
		}
		roles, err := c.roleLister.List(metav1.NamespaceAll, selector)
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

func (c *ProxyController) checkCertManagerVersion(groups []*k8smetav1.APIGroup) (string, error) {
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

func (c *ProxyController) discoverPrometheusOperator(apiList []*k8smetav1.APIResourceList) {
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
		return nil, xerrors.WithStack(err)
	}
	p, err := c.proxyLister.Get(namespace, name)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return p, nil
}

func (c *ProxyController) UpdateObject(ctx context.Context, obj interface{}) error {
	p, ok := obj.(*proxyv1alpha2.Proxy)
	if !ok {
		return nil
	}

	_, err := c.clientset.ProxyV1alpha2.UpdateProxy(ctx, p, metav1.UpdateOptions{})
	return err
}

func (c *ProxyController) Reconcile(ctx context.Context, obj interface{}) error {
	proxy := obj.(*proxyv1alpha2.Proxy)
	c.Log(ctx).Debug("Reconcile Proxy", zap.String("namespace", proxy.Namespace), zap.String("name", proxy.Name))

	if proxy.Status.Phase == "" {
		proxy.Status.Phase = proxyv1alpha2.ProxyPhaseCreating
		c.Log(ctx).Debug("Update Proxy.Status.Phase")
		updateProxy, err := c.clientset.ProxyV1alpha2.UpdateStatusProxy(ctx, proxy, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
		proxy = updateProxy
	}

	defaultResourceSelector := labels.Set(map[string]string{"app.kubernetes.io/managed-by": "heimdallr-operator", "app.kubernetes.io/instance": proxy.Name}).AsSelector()

	var backends []*proxyv1alpha2.Backend
	if len(proxy.Spec.BackendSelector.LabelSelector.MatchLabels) > 0 || len(proxy.Spec.BackendSelector.LabelSelector.MatchExpressions) > 0 {
		selector, err := metav1.LabelSelectorAsSelector(&proxy.Spec.BackendSelector.LabelSelector)
		if err != nil {
			return xerrors.WithStack(err)
		}
		b, err := c.backendLister.List(proxy.Spec.BackendSelector.Namespace, selector)
		if err != nil {
			return xerrors.WithStack(err)
		}
		backends = append(backends, b...)
	}
	defaultBackends, err := c.backendLister.List(metav1.NamespaceAll, defaultResourceSelector)
	if err != nil {
		return xerrors.WithStack(err)
	}
	if len(defaultBackends) > 0 {
		backends = append(backends, defaultBackends...)
	}

	var roles []*proxyv1alpha2.Role
	if len(proxy.Spec.RoleSelector.LabelSelector.MatchLabels) > 0 || len(proxy.Spec.RoleSelector.LabelSelector.MatchExpressions) > 0 {
		selector, err := metav1.LabelSelectorAsSelector(&proxy.Spec.RoleSelector.LabelSelector)
		if err != nil {
			return xerrors.WithStack(err)
		}
		r, err := c.roleLister.List(proxy.Spec.RoleSelector.Namespace, selector)
		if err != nil {
			return xerrors.WithStack(err)
		}
		roles = append(roles, r...)
	}
	defaultRoles, err := c.roleLister.List(metav1.NamespaceAll, defaultResourceSelector)
	if err != nil {
		return xerrors.WithStack(err)
	}
	if len(defaultRoles) > 0 {
		roles = append(roles, defaultRoles...)
	}

	var rpcPermissions []*proxyv1alpha2.RpcPermission
	if proxy.Spec.RpcPermissionSelector == nil {
		proxy.Spec.RpcPermissionSelector = &proxyv1alpha2.LabelSelector{}
	}
	if len(proxy.Spec.RpcPermissionSelector.LabelSelector.MatchLabels) > 0 || len(proxy.Spec.RpcPermissionSelector.LabelSelector.MatchExpressions) > 0 {
		selector, err := metav1.LabelSelectorAsSelector(&proxy.Spec.RpcPermissionSelector.LabelSelector)
		if err != nil {
			return xerrors.WithStack(err)
		}
		list, err := c.rpcPermissionLister.List(proxy.Spec.RpcPermissionSelector.Namespace, selector)
		if err != nil {
			return xerrors.WithStack(err)
		}
		rpcPermissions = append(rpcPermissions, list...)
	}
	defaultRpcPermissions, err := c.rpcPermissionLister.List(metav1.NamespaceAll, defaultResourceSelector)
	if err != nil {
		return xerrors.WithStack(err)
	}
	rpcPermissions = append(rpcPermissions, defaultRpcPermissions...)

	rolesMap := make(map[string]*proxyv1alpha2.Role)
	for _, v := range roles {
		rolesMap[fmt.Sprintf("%s/%s", v.Namespace, v.Name)] = v
	}
	bindings, err := c.roleBindingLister.List(metav1.NamespaceAll, labels.Everything())
	if err != nil {
		return xerrors.WithStack(err)
	}
	roleBindings := RoleBindings(bindings).Select(func(binding *proxyv1alpha2.RoleBinding) bool {
		_, ok := rolesMap[fmt.Sprintf("%s/%s", binding.RoleRef.Namespace, binding.RoleRef.Name)]
		return ok
	})

	lp := NewHeimdallrProxy(HeimdallrProxyParams{
		Spec:                proxy,
		ThirdPartyClientSet: c.thirdPartyClientSet,
		ServiceLister:       c.serviceLister,
		Backends:            backends,
		Roles:               roles,
		RpcPermissions:      rpcPermissions,
		RoleBindings:        roleBindings,
		CertManagerVersion:  c.certManagerVersion,
	})
	if ec, err := c.ownedEtcdCluster(lp); err != nil && !apierrors.IsNotFound(err) {
		return err
	} else if ec != nil {
		lp.Datastore = ec
	}
	if err := lp.Init(c.secretLister); err != nil {
		return err
	}

	if err := c.preCheck(lp); err != nil {
		if apierrors.IsNotFound(errors.Unwrap(err)) {
			c.EventRecorder().Eventf(lp.Object, corev1.EventTypeWarning, "InvalidSpec", "Failure pre-check %v", err)
		}
		newP := lp.Object.DeepCopy()
		newP.Status.Phase = proxyv1alpha2.ProxyPhaseError
		if !reflect.DeepEqual(newP.Status, lp.Object.Status) {
			_, err := c.clientset.ProxyV1alpha2.UpdateStatusProxy(ctx, newP, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.WithStack(err)
			}
		}

		return err
	}
	if err := c.prepare(ctx, lp); err != nil {
		return err
	}

	newP := lp.Object.DeepCopy()
	newP.Status.CASecretName = lp.CASecretName()
	newP.Status.SigningPrivateKeySecretName = lp.PrivateKeySecretName()
	newP.Status.GithubWebhookSecretName = lp.GithubSecretName()
	newP.Status.CookieSecretName = lp.CookieSecretName()
	newP.Status.InternalTokenSecretName = lp.InternalTokenSecretName()

	if !reflect.DeepEqual(newP.Status, lp.Object.Status) {
		c.Log(ctx).Debug("Update Proxy")
		_, err := c.clientset.ProxyV1alpha2.UpdateStatusProxy(ctx, newP, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
	}

	rpcReady, err := c.reconcileRPCServer(ctx, lp)
	if err != nil {
		return err
	}

	if !rpcReady {
		return controllerbase.WrapRetryError(xerrors.WithStack(ErrRPCServerIsNotReady))
	}

	if err := c.reconcileProxyProcess(ctx, lp); err != nil {
		return err
	}

	if err := c.reconcileDashboard(ctx, lp); err != nil {
		return err
	}

	if err := c.finishReconcile(ctx, lp); err != nil {
		return err
	}

	return nil
}

func (c *ProxyController) Finalize(_ context.Context, _ interface{}) error {
	return nil
}

func (c *ProxyController) ownedEtcdCluster(lp *HeimdallrProxy) (*etcdv1alpha2.EtcdCluster, error) {
	return c.ecLister.Get(lp.Namespace, lp.EtcdClusterName())
}

func (c *ProxyController) preCheck(lp *HeimdallrProxy) error {
	_, err := c.secretLister.Get(lp.Namespace, lp.Spec.IdentityProvider.ClientSecretRef.Name)
	if err != nil && apierrors.IsNotFound(err) {
		return xerrors.WithStack(err)
	}

	return nil
}

func (c *ProxyController) prepare(ctx context.Context, lp *HeimdallrProxy) error {
	secrets := lp.Secrets()
	for _, secret := range secrets {
		if secret.Known() {
			if err := c.removeOwnerReferenceFromSecret(ctx, lp, secret.Name); err != nil {
				return err
			}

			continue
		}

		_, err := c.secretLister.Get(lp.Namespace, secret.Name)
		if err != nil && apierrors.IsNotFound(err) {
			secret, err := secret.Create()
			if err != nil {
				return err
			}

			_, err = c.client.CoreV1.CreateSecret(ctx, secret, metav1.CreateOptions{})
			if err != nil {
				return xerrors.WithStack(err)
			}
		} else if err != nil {
			return xerrors.WithStack(err)
		}
	}

	serverCert := lp.Certificate()
	if err := c.createOrUpdateCertificate(ctx, lp, serverCert); err != nil {
		return err
	}

	_, err := c.secretLister.Get(lp.Namespace, lp.CertificateSecretName())
	if err != nil {
		return controllerbase.WrapRetryError(xerrors.WithStack(err))
	}

	if err := c.reconcileFundamentalResources(ctx, lp); err != nil {
		return err
	}

	if err := c.reconcileEtcdCluster(ctx, lp); err != nil {
		return err
	}

	return nil
}

func (c *ProxyController) removeOwnerReferenceFromSecret(ctx context.Context, lp *HeimdallrProxy, secretName string) error {
	if lp.Object.UID == "" {
		return nil
	}

	s, err := c.secretLister.Get(lp.Namespace, secretName)
	if err != nil {
		return xerrors.WithStack(err)
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
	s.OwnerReferences = newRef
	_, err = c.client.CoreV1.UpdateSecret(ctx, s, metav1.UpdateOptions{})
	if err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func (c *ProxyController) reconcileFundamentalResources(ctx context.Context, lp *HeimdallrProxy) error {
	backends := lp.DefaultBackends()
	for _, backend := range backends {
		_, err := c.backendLister.Get(backend.Namespace, backend.Name)
		if apierrors.IsNotFound(err) {
			lp.ControlObject(backend)
			_, err = c.clientset.ProxyV1alpha2.CreateBackend(ctx, backend, metav1.CreateOptions{})
			if err != nil {
				return xerrors.WithStack(err)
			}
		}
	}

	roles := lp.DefaultRoles()
	for _, role := range roles {
		_, err := c.roleLister.Get(role.Namespace, role.Name)
		if apierrors.IsNotFound(err) {
			lp.ControlObject(role)
			_, err = c.clientset.ProxyV1alpha2.CreateRole(ctx, role, metav1.CreateOptions{})
			if err != nil {
				return xerrors.WithStack(err)
			}
		}
	}

	roleBindings := lp.DefaultRoleBindings()
	for _, rb := range roleBindings {
		_, err := c.roleBindingLister.Get(rb.Namespace, rb.Name)
		if apierrors.IsNotFound(err) {
			lp.ControlObject(rb)
			_, err = c.clientset.ProxyV1alpha2.CreateRoleBinding(ctx, rb, metav1.CreateOptions{})
			if err != nil {
				return xerrors.WithStack(err)
			}
		}
	}

	rpcPermissions := lp.DefaultRpcPermissions()
	for _, rpcPermission := range rpcPermissions {
		_, err := c.rpcPermissionLister.Get(rpcPermission.Namespace, rpcPermission.Name)
		if apierrors.IsNotFound(err) {
			lp.ControlObject(rpcPermission)
			_, err = c.clientset.ProxyV1alpha2.CreateRpcPermission(ctx, rpcPermission, metav1.CreateOptions{})
			if err != nil {
				return xerrors.WithStack(err)
			}
		}
	}

	return nil
}

func (c *ProxyController) reconcileEtcdCluster(ctx context.Context, lp *HeimdallrProxy) error {
	newC, newPM := lp.EtcdCluster()

	cluster, err := c.ecLister.Get(lp.Namespace, lp.EtcdClusterName())
	if err != nil {
		if apierrors.IsNotFound(err) {
			cluster, err = c.clientset.EtcdV1alpha2.CreateEtcdCluster(ctx, newC, metav1.CreateOptions{})
			if err != nil {
				return xerrors.WithStack(err)
			}

			return controllerbase.WrapRetryError(xerrors.WithStack(ErrEtcdClusterIsNotReady))
		}

		return xerrors.WithStack(err)
	}

	if !cluster.Status.Ready {
		return controllerbase.WrapRetryError(xerrors.WithStack(ErrEtcdClusterIsNotReady))
	}

	var podMonitor *monitoringv1.PodMonitor
	if c.enablePrometheusOperator && lp.Spec.Monitor.PrometheusMonitoring {
		podMonitor, err = c.pmLister.Get(lp.Namespace, newPM.Name)
		if err != nil {
			if apierrors.IsNotFound(err) {
				_, err = c.thirdPartyClientSet.CoreosComV1.CreatePodMonitor(ctx, newPM, metav1.CreateOptions{})
				if err != nil {
					return xerrors.WithStack(err)
				}
				return nil
			}

			return xerrors.WithStack(err)
		}
	}

	if !reflect.DeepEqual(newC.Spec, cluster.Spec) {
		cluster.Spec = newC.Spec
		_, err = c.clientset.EtcdV1alpha2.UpdateEtcdCluster(ctx, cluster, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
	}

	if podMonitor != nil && newPM != nil {
		if !reflect.DeepEqual(podMonitor.Labels, newPM.Labels) || !reflect.DeepEqual(podMonitor.Spec, newPM.Spec) {
			podMonitor.Spec = newPM.Spec
			podMonitor.Labels = newPM.Labels
			_, err = c.thirdPartyClientSet.CoreosComV1.UpdatePodMonitor(ctx, podMonitor, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.WithStack(err)
			}
		}
	}

	return nil
}

func (c *ProxyController) reconcileRPCServer(ctx context.Context, lp *HeimdallrProxy) (bool, error) {
	objs, err := lp.IdealRPCServer()
	if err != nil {
		return false, err
	}

	if err := c.reconcileProcess(ctx, lp, objs); err != nil {
		return false, err
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
		return err
	}

	err = c.reconcileProcess(ctx, lp, objs)
	if err != nil {
		return err
	}
	lp.DashboardServer = objs

	return nil
}

func (c *ProxyController) reconcileProxyProcess(ctx context.Context, lp *HeimdallrProxy) error {
	_, err := c.secretLister.Get(lp.Namespace, lp.Spec.IdentityProvider.ClientSecretRef.Name)
	if err != nil && apierrors.IsNotFound(err) {
		return xerrors.WithStack(err)
	}

	pcs, err := lp.IdealProxyProcess()
	if err != nil {
		return err
	}

	err = c.reconcileProcess(ctx, lp, pcs)
	if err != nil {
		return err
	}
	lp.ProxyServer = pcs

	for _, backend := range lp.Backends() {
		skipProvision := false
		for _, v := range backend.Spec.HTTP {
			if v.ServiceSelector != nil {
				_, err := findService(c.serviceLister, v.ServiceSelector, backend.Namespace)
				if err != nil && !backend.CreationTimestamp.IsZero() {
					skipProvision = true
					c.EventRecorder().Event(backend, corev1.EventTypeWarning, "FindServiceError", err.Error())
				}
			}
		}

		found := false
		for _, v := range backend.Status.DeployedBy {
			if v.Name == lp.Name && v.Namespace == lp.Namespace {
				found = true
				break
			}
		}

		hostname := fmt.Sprintf("%s.%s.%s", backend.Name, backend.Spec.Layer, lp.Spec.Domain)
		if backend.Spec.Layer == "" {
			hostname = fmt.Sprintf("%s.%s", backend.Name, lp.Spec.Domain)
		}
		if backend.Spec.FQDN != "" {
			hostname = backend.Spec.FQDN
		}
		if !found && !skipProvision && !backend.CreationTimestamp.IsZero() {
			err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				updatedB, err := c.backendLister.Get(backend.Namespace, backend.Name)
				if err != nil {
					return err
				}

				updatedB.Status.DeployedBy = append(updatedB.Status.DeployedBy, proxyv1alpha2.ProxyReference{
					Name:      lp.Name,
					Namespace: lp.Namespace,
					Url:       fmt.Sprintf("https://%s", hostname),
				})

				_, err = c.clientset.ProxyV1alpha2.UpdateStatusBackend(ctx, updatedB, metav1.UpdateOptions{})
				return err
			})
			if err != nil {
				return xerrors.WithStack(err)
			}
		}

		if _, ok := backend.Annotations[proxy.AnnotationKeyIngressName]; !ok {
			continue
		}
		ns, name, err := cache.SplitMetaNamespaceKey(backend.Annotations[proxy.AnnotationKeyIngressName])
		if err != nil {
			c.Log(ctx).Warn("Could not parse annotation key which contains Ingress name", zap.Error(err))
			continue
		}
		ingress, err := c.ingressLister.Get(ns, name)
		if err != nil && apierrors.IsNotFound(err) {
			c.Log(ctx).Info("Skip updating Ingress")
			continue
		} else if err != nil {
			return xerrors.WithStack(err)
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
		updatedI.Status.LoadBalancer.Ingress = append(updatedI.Status.LoadBalancer.Ingress, networkingv1.IngressLoadBalancerIngress{
			Hostname: hostname,
		})
		if !reflect.DeepEqual(updatedI.Status, ingress.Status) {
			_, err = c.client.NetworkingK8sIoV1.UpdateStatusIngress(ctx, updatedI, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.WithStack(err)
			}
		}
	}

	roles := make(map[string]*proxyv1alpha2.Role)
	for _, v := range lp.Roles() {
		role := v.DeepCopy()
		role.Status.Backends = nil
		roles[fmt.Sprintf("%s/%s", v.Namespace, v.Name)] = role
	}
	for _, rb := range lp.RoleBindings() {
		role, ok := roles[fmt.Sprintf("%s/%s", rb.RoleRef.Namespace, rb.RoleRef.Name)]
		if !ok {
			continue
		}

		for _, s := range rb.Subjects {
			namespace := s.Namespace
			if namespace == "" {
				namespace = rb.Namespace
			}
			role.Status.Backends = append(role.Status.Backends, fmt.Sprintf("%s/%s/%s", namespace, s.Name, s.Permission))
		}
	}
	for _, r := range lp.Roles() {
		newRole := roles[fmt.Sprintf("%s/%s", r.Namespace, r.Name)]
		uniq := make(map[string]struct{})
		for _, v := range newRole.Status.Backends {
			uniq[v] = struct{}{}
		}
		backends := make([]string, 0, len(uniq))
		for k := range uniq {
			backends = append(backends, k)
		}
		sort.Strings(backends)

		if !reflect.DeepEqual(newRole.Status, r.Status) {
			err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				updatedR, err := c.roleLister.Get(newRole.Namespace, newRole.Name)
				if err != nil {
					return err
				}

				updatedR.Status.Backends = backends
				_, err = c.clientset.ProxyV1alpha2.UpdateStatusRole(ctx, updatedR, metav1.UpdateOptions{})
				return err
			})
			if err != nil {
				return xerrors.WithStack(err)
			}
		}
	}

	return nil
}

func (c *ProxyController) finishReconcile(ctx context.Context, lp *HeimdallrProxy) error {
	newP := lp.Object.DeepCopy()
	newP.Status.Ready = c.isReady(lp)
	newP.Status.Phase = proxyv1alpha2.ProxyPhaseRunning
	newP.Status.CASecretName = lp.CASecretName()
	newP.Status.SigningPrivateKeySecretName = lp.PrivateKeySecretName()
	newP.Status.GithubWebhookSecretName = lp.GithubSecretName()
	newP.Status.CookieSecretName = lp.CookieSecretName()
	newP.Status.InternalTokenSecretName = lp.InternalTokenSecretName()

	if !reflect.DeepEqual(newP.Status, lp.Object.Status) {
		_, err := c.clientset.ProxyV1alpha2.UpdateStatusProxy(ctx, newP, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
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
	if d.Status.ReadyReplicas < d.Spec.Replicas {
		return false
	}

	return true
}

func (c *ProxyController) reconcileProcess(ctx context.Context, lp *HeimdallrProxy, p *process) error {
	if p.Deployment != nil {
		if err := c.createOrUpdateDeployment(ctx, lp, p.Deployment); err != nil {
			return err
		}
	}

	if p.PodDisruptionBudget != nil {
		if err := c.createOrUpdatePodDisruptionBudget(ctx, lp, p.PodDisruptionBudget); err != nil {
			return err
		}
	}

	for _, svc := range p.Service {
		if svc == nil {
			continue
		}

		if err := c.createOrUpdateService(ctx, lp, svc); err != nil {
			return err
		}
	}

	for _, v := range p.ConfigMaps {
		if v == nil {
			continue
		}

		if err := c.createOrUpdateConfigMap(ctx, lp, v); err != nil {
			return err
		}
	}

	if p.Certificate != nil {
		if err := c.createOrUpdateCertificate(ctx, lp, p.Certificate); err != nil {
			return err
		}
	}

	if c.enablePrometheusOperator {
		for _, v := range p.ServiceMonitors {
			if v == nil {
				continue
			}

			if err := c.createOrUpdateServiceMonitor(ctx, lp, v); err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateDeployment(ctx context.Context, lp *HeimdallrProxy, deployment *appsv1.Deployment) error {
	d, err := c.deploymentLister.Get(deployment.Namespace, deployment.Name)
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(deployment)

		newD, err := c.client.AppsV1.CreateDeployment(ctx, deployment, metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}

		deployment.Status = newD.Status
		return nil
	} else if err != nil {
		return xerrors.WithStack(err)
	}

	newD := d.DeepCopy()
	newD.Spec = deployment.Spec
	if !reflect.DeepEqual(newD.Spec, d.Spec) {
		_, err = c.client.AppsV1.UpdateDeployment(ctx, newD, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
	}
	deployment.Status = d.Status

	return nil
}

func (c *ProxyController) createOrUpdatePodDisruptionBudget(ctx context.Context, lp *HeimdallrProxy, pdb *policyv1.PodDisruptionBudget) error {
	p, err := c.client.PolicyV1.GetPodDisruptionBudget(ctx, pdb.Namespace, pdb.Name, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(pdb)

		_, err = c.client.PolicyV1.CreatePodDisruptionBudget(ctx, pdb, metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}

		return nil
	} else if err != nil {
		return xerrors.WithStack(err)
	}

	newPDB := p.DeepCopy()
	newPDB.Spec = pdb.Spec
	if !reflect.DeepEqual(newPDB.Spec, pdb.Spec) {
		_, err = c.client.PolicyV1.UpdatePodDisruptionBudget(ctx, newPDB, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateService(ctx context.Context, lp *HeimdallrProxy, svc *corev1.Service) error {
	s, err := c.serviceLister.Get(svc.Namespace, svc.Name)
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(svc)

		_, err = c.client.CoreV1.CreateService(ctx, svc, metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}

		return nil
	} else if err != nil {
		return xerrors.WithStack(err)
	}

	newS := s.DeepCopy()
	newS.Labels = svc.Labels
	newS.Spec.Selector = svc.Spec.Selector
	newS.Spec.Type = svc.Spec.Type
	newS.Spec.Ports = svc.Spec.Ports
	if !c.equalService(newS, s) {
		_, err = c.client.CoreV1.UpdateService(ctx, newS, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateConfigMap(ctx context.Context, lp *HeimdallrProxy, configMap *corev1.ConfigMap) error {
	cm, err := c.configMapLister.Get(configMap.Namespace, configMap.Name)
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(configMap)

		_, err = c.client.CoreV1.CreateConfigMap(ctx, configMap, metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}

		return nil
	} else if err != nil {
		return xerrors.WithStack(err)
	}

	newCM := cm.DeepCopy()
	newCM.Data = configMap.Data

	if !reflect.DeepEqual(newCM.Data, cm.Data) {
		c.Log(ctx).Debug("Will update ConfigMap", zap.String("diff", cmp.Diff(cm.Data, newCM.Data)))
		_, err = c.client.CoreV1.UpdateConfigMap(ctx, newCM, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateCertificate(ctx context.Context, lp *HeimdallrProxy, obj runtime.Object) error {
	switch certificate := obj.(type) {
	case *certmanagerv1.Certificate:
		crt, err := c.thirdPartyClientSet.CertManagerV1.GetCertificate(ctx, certificate.Namespace, certificate.Name, metav1.GetOptions{})
		if err != nil && apierrors.IsNotFound(err) {
			lp.ControlObject(certificate)

			_, err = c.thirdPartyClientSet.CertManagerV1.CreateCertificate(ctx, certificate, metav1.CreateOptions{})
			if err != nil {
				return xerrors.WithStack(err)
			}

			return nil
		} else if err != nil {
			return xerrors.WithStack(err)
		}

		newCRT := crt.DeepCopy()
		newCRT.Spec = certificate.Spec

		if !reflect.DeepEqual(newCRT.Spec, crt.Spec) {
			_, err = c.thirdPartyClientSet.CertManagerV1.UpdateCertificate(ctx, newCRT, metav1.UpdateOptions{})
			if err != nil {
				return xerrors.WithStack(err)
			}
		}
	}

	return nil
}

func (c *ProxyController) createOrUpdateServiceMonitor(ctx context.Context, lp *HeimdallrProxy, serviceMonitor *monitoringv1.ServiceMonitor) error {
	sm, err := c.thirdPartyClientSet.CoreosComV1.GetServiceMonitor(ctx, serviceMonitor.Namespace, serviceMonitor.Name, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(serviceMonitor)

		_, err = c.thirdPartyClientSet.CoreosComV1.CreateServiceMonitor(ctx, serviceMonitor, metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}

		return nil
	} else if err != nil {
		return xerrors.WithStack(err)
	}

	newSM := sm.DeepCopy()
	newSM.Labels = serviceMonitor.Labels
	newSM.Spec = serviceMonitor.Spec

	if !reflect.DeepEqual(newSM.Spec, sm.Spec) || !reflect.DeepEqual(newSM.ObjectMeta, sm.ObjectMeta) {
		_, err = c.thirdPartyClientSet.CoreosComV1.UpdateServiceMonitor(ctx, newSM, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
	}

	return nil
}

func (c *ProxyController) searchParentProxy(m metav1.Object) ([]*proxyv1alpha2.Proxy, error) {
	ret, err := c.proxyLister.List(metav1.NamespaceAll, labels.Everything())
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	targets := make([]*proxyv1alpha2.Proxy, 0)
Item:
	for _, v := range ret {
		if m.GetObjectMeta().Labels != nil {
			for k := range v.Spec.BackendSelector.LabelSelector.MatchLabels {
				value, ok := m.GetObjectMeta().Labels[k]
				if !ok || v.Spec.BackendSelector.LabelSelector.MatchLabels[k] != value {
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
		if leftTP != nil && rightTP != nil && leftTP.IntValue() != rightTP.IntValue() {
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
