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
	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmClientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"golang.org/x/xerrors"
	appsv1 "k8s.io/api/apps/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/klog"

	proxyv1 "github.com/f110/lagrangian-proxy/operator/pkg/api/proxy/v1"
	clientset "github.com/f110/lagrangian-proxy/operator/pkg/client/versioned"
	informers "github.com/f110/lagrangian-proxy/operator/pkg/informers/externalversions"
	etcdListers "github.com/f110/lagrangian-proxy/operator/pkg/listers/etcd/v1alpha1"
	proxyListers "github.com/f110/lagrangian-proxy/operator/pkg/listers/proxy/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
)

// +kubebuilder:rbac:groups=proxy.f110.dev,resources=proxies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=proxies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=backends,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=backends/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=roles,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=roles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=rpcpermissions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=rpcpermissions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=etcd.f110.dev,resources=etcdclusters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=*,resources=secrets;configmaps;services;cronjob;deployments;poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=monitoring.coreos.com,resources=podmonitors,servicemonitors,verbs=get;list;watch;create;update;patch;delete

type Controller struct {
	schema.GroupVersionKind

	client                    *kubernetes.Clientset
	proxyLister               proxyListers.ProxyLister
	proxyListerSynced         cache.InformerSynced
	backendLister             proxyListers.BackendLister
	backendListerSynced       cache.InformerSynced
	roleLister                proxyListers.RoleLister
	roleListerSynced          cache.InformerSynced
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

func New(ctx context.Context, client *kubernetes.Clientset, cfg *rest.Config) (*Controller, error) {
	proxyClient, err := clientset.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	sharedInformer := informers.NewSharedInformerFactory(proxyClient, 30*time.Second)
	proxyInformer := sharedInformer.Proxy().V1().Proxies()
	backendInformer := sharedInformer.Proxy().V1().Backends()
	roleInformer := sharedInformer.Proxy().V1().Roles()
	rpcPermissionInformer := sharedInformer.Proxy().V1().RpcPermissions()
	ecInformer := sharedInformer.Etcd().V1alpha1().EtcdClusters()

	cmClient, err := cmClientset.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	c := &Controller{
		client:      client,
		clientset:   proxyClient,
		cmClientset: cmClient,
		queue:       workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Etcd"),
	}

	_, apiList, err := client.ServerGroupsAndResources()
	if err != nil {
		return nil, err
	}
	if err := c.checkCustomResource(apiList, "cert-manager.io/v1alpha2", "Certificate"); err != nil {
		return nil, err
	}
	c.discoverPrometheusOperator(apiList)

	if c.enablePrometheusOperator {
		mClient, err := mClientset.NewForConfig(cfg)
		if err != nil {
			return nil, err
		}
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

	rpcPermissionInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addRpcPermission,
		UpdateFunc: c.updateRpcPermission,
		DeleteFunc: c.deleteRpcPermission,
	})
	c.rpcPermissionLister = rpcPermissionInformer.Lister()
	c.rpcPermissionListerSynced = rpcPermissionInformer.Informer().HasSynced

	c.ecLister = ecInformer.Lister()
	c.ecListerSynced = ecInformer.Informer().HasSynced

	sharedInformer.Start(ctx.Done())

	return c, nil
}

func (c *Controller) Run(ctx context.Context, workers int) {
	defer c.queue.ShutDown()

	if !cache.WaitForNamedCacheSync(c.Kind, ctx.Done(),
		c.ecListerSynced,
		c.rpcPermissionListerSynced,
		c.roleListerSynced,
		c.backendListerSynced,
		c.proxyListerSynced,
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

func (c *Controller) checkCustomResource(apiList []*metav1.APIResourceList, groupVersion, kind string) error {
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

func (c *Controller) discoverPrometheusOperator(apiList []*metav1.APIResourceList) {
	for _, v := range apiList {
		if v.GroupVersion == "monitoring.coreos.com/v1" {
			c.enablePrometheusOperator = true
			return
		}
	}
}

func (c *Controller) worker() {
	for c.processNextItem() {
	}
}

func (c *Controller) processNextItem() bool {
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

func (c *Controller) syncProxy(key string) error {
	klog.V(4).Info("syncProxy")

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	proxy, err := c.proxyLister.Proxies(namespace).Get(name)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	selector, err := metav1.LabelSelectorAsSelector(&proxy.Spec.BackendSelector.LabelSelector)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	backends, err := c.clientset.ProxyV1().Backends("").List(metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	selector, err = metav1.LabelSelectorAsSelector(&proxy.Spec.RoleSelector.LabelSelector)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	roles, err := c.clientset.ProxyV1().Roles("").List(metav1.ListOptions{LabelSelector: selector.String()})

	selector, err = metav1.LabelSelectorAsSelector(&proxy.Spec.RpcPermissionSelector.LabelSelector)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	rpcPermissions, err := c.clientset.ProxyV1().RpcPermissions("").List(metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	lp := NewLagrangianProxy(proxy, c.client, c.clientset, c.cmClientset, backends.Items, roles.Items, rpcPermissions.Items)
	if err := c.prepare(lp); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := c.reconcileRPCServer(lp); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := c.reconcileMainProcess(lp); err != nil {
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

func (c *Controller) prepare(lp *LagrangianProxy) error {
	if err := c.reconcileEtcdCluster(lp); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	// Setup CA if not set up.
	_, err := c.client.CoreV1().Secrets(lp.Namespace).Get(lp.CASecretName(), metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		newS, err := lp.SetupCA()
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		lp.ControlObject(newS)
		_, err = c.client.CoreV1().Secrets(lp.Namespace).Create(newS)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (c *Controller) reconcileEtcdCluster(lp *LagrangianProxy) error {
	newC, newPM := lp.EtcdCluster()

	cluster, err := c.ecLister.EtcdClusters(lp.Namespace).Get(lp.EtcdClusterName())
	if err != nil {
		if apierrors.IsNotFound(err) {
			cluster, err = c.clientset.EtcdV1alpha1().EtcdClusters(lp.Namespace).Create(newC)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}

			return WrapRetryError(errors.New("EtcdCluster is not ready yet"))
		}

		return xerrors.Errorf(": %w", err)
	}

	if !cluster.Status.Ready {
		return WrapRetryError(errors.New("EtcdCluster is not ready yet"))
	}

	var podMonitor *monitoringv1.PodMonitor
	if c.enablePrometheusOperator && lp.Spec.Monitor.PrometheusMonitoring {
		podMonitor, err = c.pmLister.PodMonitors(lp.Namespace).Get(lp.EtcdClusterName())
		if err != nil {
			if apierrors.IsNotFound(err) {
				_, err = c.monitoringClientset.MonitoringV1().PodMonitors(lp.Namespace).Create(newPM)
				if err != nil {
					return xerrors.Errorf(": %w", err)
				}
			}

			return xerrors.Errorf(": %w", err)
		}
	}

	if !reflect.DeepEqual(newC.Spec, cluster.Spec) {
		_, err = c.clientset.EtcdV1alpha1().EtcdClusters(lp.Namespace).Update(newC)
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

func (c *Controller) reconcileRPCServer(lp *LagrangianProxy) error {
	objs, err := lp.RPCServer()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := c.reconcileProcess(lp, objs); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	return nil
}

func (c *Controller) reconcileDashboard(lp *LagrangianProxy) error {
	objs, err := lp.Dashboard()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	err = c.reconcileProcess(lp, objs)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (c *Controller) reconcileMainProcess(lp *LagrangianProxy) error {
	_, err := c.client.CoreV1().Secrets(lp.Namespace).Get(lp.Spec.IdentityProvider.ClientSecretRef.Name, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		return xerrors.Errorf(": %w", err)
	}

	objs, err := lp.Main()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	err = c.reconcileProcess(lp, objs)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (c *Controller) finishReconcile(lp *LagrangianProxy) error {
	newP := lp.Object.DeepCopy()
	newP.Status.Ready = true
	newP.Status.Phase = "Running"

	if !reflect.DeepEqual(newP.Status, lp.Object.Status) {
		_, err := c.clientset.ProxyV1().Proxies(newP.Namespace).Update(newP)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}
	return nil
}

func (c *Controller) reconcileProcess(lp *LagrangianProxy, p *process) error {
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
			return err
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

	if p.CronJob != nil {
		if err := c.createOrUpdateCronJob(lp, p.CronJob); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if p.Certificate != nil {
		if err := c.createOrUpdateCertificate(lp, p.Certificate); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	for _, v := range p.Secrets {
		if v == nil {
			continue
		}

		if err := c.createOrUpdateSecret(lp, v); err != nil {
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

func (c *Controller) createOrUpdateDeployment(lp *LagrangianProxy, deployment *appsv1.Deployment) error {
	d, err := c.client.AppsV1().Deployments(deployment.Namespace).Get(deployment.Name, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(deployment)

		_, err = c.client.AppsV1().Deployments(deployment.Namespace).Create(deployment)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

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

	return nil
}

func (c *Controller) createOrUpdatePodDisruptionBudget(lp *LagrangianProxy, pdb *policyv1beta1.PodDisruptionBudget) error {
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

func (c *Controller) createOrUpdateService(lp *LagrangianProxy, svc *corev1.Service) error {
	s, err := c.client.CoreV1().Services(svc.Namespace).Get(svc.Name, metav1.GetOptions{})
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

func (c *Controller) createOrUpdateConfigMap(lp *LagrangianProxy, configMap *corev1.ConfigMap) error {
	cm, err := c.client.CoreV1().ConfigMaps(configMap.Namespace).Get(configMap.Name, metav1.GetOptions{})
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
	newCM.Data = cm.Data

	if !reflect.DeepEqual(newCM.Data, cm.Data) {
		_, err = c.client.CoreV1().ConfigMaps(newCM.Namespace).Update(newCM)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (c *Controller) createOrUpdateCronJob(lp *LagrangianProxy, cronJob *batchv1beta1.CronJob) error {
	cj, err := c.client.BatchV1beta1().CronJobs(cronJob.Namespace).Get(cronJob.Name, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(cronJob)

		_, err = c.client.BatchV1beta1().CronJobs(cronJob.Namespace).Create(cronJob)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		return nil
	} else if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	newCJ := cj.DeepCopy()
	newCJ.Spec = cronJob.Spec

	if !reflect.DeepEqual(newCJ.Spec, cj.Spec) {
		_, err = c.client.BatchV1beta1().CronJobs(newCJ.Namespace).Update(newCJ)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (c *Controller) createOrUpdateCertificate(lp *LagrangianProxy, certificate *certmanager.Certificate) error {
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

func (c *Controller) createOrUpdateSecret(lp *LagrangianProxy, secret *corev1.Secret) error {
	s, err := c.client.CoreV1().Secrets(secret.Namespace).Get(secret.Name, metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		lp.ControlObject(secret)

		_, err = c.client.CoreV1().Secrets(secret.Namespace).Create(secret)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		return nil
	} else if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	newS := s.DeepCopy()
	newS.Data = secret.Data

	if !reflect.DeepEqual(newS.Data, s.Data) {
		_, err = c.client.CoreV1().Secrets(newS.Namespace).Update(newS)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (c *Controller) createOrUpdateServiceMonitor(lp *LagrangianProxy, serviceMonitor *monitoringv1.ServiceMonitor) error {
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

func (c *Controller) searchParentProxy(m *metav1.ObjectMeta) ([]*proxyv1.Proxy, error) {
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

func (c *Controller) enqueue(proxy *proxyv1.Proxy) {
	if key, err := cache.MetaNamespaceKeyFunc(proxy); err != nil {
		return
	} else {
		c.queue.Add(key)
	}
}

func (c *Controller) enqueueSubordinateResource(m *metav1.ObjectMeta) error {
	ret, err := c.searchParentProxy(m)
	if err != nil {
		return err
	}

	for _, v := range ret {
		c.enqueue(v)
	}

	return nil
}

func (c *Controller) addProxy(obj interface{}) {
	proxy := obj.(*proxyv1.Proxy)

	c.enqueue(proxy)
}

func (c *Controller) updateProxy(before, after interface{}) {
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

func (c *Controller) deleteProxy(obj interface{}) {
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

func (c *Controller) addBackend(obj interface{}) {
	backend := obj.(*proxyv1.Backend)

	if err := c.enqueueSubordinateResource(&backend.ObjectMeta); err != nil {
		return
	}
}

func (c *Controller) updateBackend(before, after interface{}) {
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

func (c *Controller) deleteBackend(obj interface{}) {
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

func (c *Controller) addRole(obj interface{}) {
	role := obj.(*proxyv1.Role)

	if err := c.enqueueSubordinateResource(&role.ObjectMeta); err != nil {
		return
	}
}

func (c *Controller) updateRole(before, after interface{}) {
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

func (c *Controller) deleteRole(obj interface{}) {
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

func (c *Controller) addRpcPermission(obj interface{}) {
	rpcPermission := obj.(*proxyv1.RpcPermission)

	if err := c.enqueueSubordinateResource(&rpcPermission.ObjectMeta); err != nil {
		return
	}
}

func (c *Controller) updateRpcPermission(before, after interface{}) {
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

func (c *Controller) deleteRpcPermission(obj interface{}) {
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
