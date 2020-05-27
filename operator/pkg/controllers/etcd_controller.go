package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"

	"go.etcd.io/etcd/v3/etcdserver/etcdserverpb"
	"golang.org/x/xerrors"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/util/wait"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/transport/spdy"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"

	"github.com/f110/lagrangian-proxy/operator/pkg/api/etcd"
	etcdv1alpha1 "github.com/f110/lagrangian-proxy/operator/pkg/api/etcd/v1alpha1"
	clientset "github.com/f110/lagrangian-proxy/operator/pkg/client/versioned"
	"github.com/f110/lagrangian-proxy/operator/pkg/client/versioned/scheme"
	informers "github.com/f110/lagrangian-proxy/operator/pkg/informers/externalversions"
	etcdlisters "github.com/f110/lagrangian-proxy/operator/pkg/listers/etcd/v1alpha1"
)

const (
	defaultEtcdVersion = "v3.4.0"
)

type EtcdController struct {
	schema.GroupVersionKind

	config            *rest.Config
	client            *kubernetes.Clientset
	ecClient          clientset.Interface
	clusterDomain     string
	runOutsideCluster bool

	clusterLister       etcdlisters.EtcdClusterLister
	clusterListerSynced cache.InformerSynced
	podLister           listers.PodLister
	podListerSynced     cache.InformerSynced
	serviceLister       listers.ServiceLister
	serviceListerSynced cache.InformerSynced
	secretLister        listers.SecretLister
	secretListerSynced  cache.InformerSynced

	queue    workqueue.RateLimitingInterface
	recorder record.EventRecorder
}

func NewEtcdController(
	sharedInformerFactory informers.SharedInformerFactory,
	coreSharedInformerFactory kubeinformers.SharedInformerFactory,
	client *kubernetes.Clientset,
	cfg *rest.Config,
	clusterDomain string,
	runOutsideCluster bool,
) (*EtcdController, error) {
	etcdClient, err := clientset.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	podInformer := coreSharedInformerFactory.Core().V1().Pods()
	serviceInformer := coreSharedInformerFactory.Core().V1().Services()
	secretInformer := coreSharedInformerFactory.Core().V1().Secrets()

	etcdClusterInformer := sharedInformerFactory.Etcd().V1alpha1().EtcdClusters()

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: client.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "etcd-controller"})

	c := &EtcdController{
		config:              cfg,
		client:              client,
		ecClient:            etcdClient,
		clusterDomain:       clusterDomain,
		runOutsideCluster:   runOutsideCluster,
		clusterLister:       etcdClusterInformer.Lister(),
		clusterListerSynced: etcdClusterInformer.Informer().HasSynced,
		podLister:           podInformer.Lister(),
		podListerSynced:     podInformer.Informer().HasSynced,
		serviceLister:       serviceInformer.Lister(),
		serviceListerSynced: serviceInformer.Informer().HasSynced,
		secretLister:        secretInformer.Lister(),
		secretListerSynced:  secretInformer.Informer().HasSynced,
		queue:               workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Etcd"),
		recorder:            recorder,
	}

	etcdClusterInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addEtcdCluster,
		UpdateFunc: c.updateEtcdCluster,
		DeleteFunc: c.deleteEtcdCluster,
	})
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: c.updatePod,
		DeleteFunc: c.deletePod,
	})

	return c, nil
}

func (ec *EtcdController) Run(ctx context.Context, workers int) {
	defer ec.queue.ShutDown()

	klog.Info("Wait for informer caches to sync")
	if !cache.WaitForCacheSync(ctx.Done(),
		ec.clusterListerSynced,
		ec.podListerSynced,
		ec.serviceListerSynced,
		ec.secretListerSynced,
	) {
		klog.Error("Failed to sync informer caches")
		return
	}

	for i := 0; i < workers; i++ {
		go wait.Until(ec.worker, time.Second, ctx.Done())
	}

	klog.V(2).Info("Start workers of EtcdController")
	<-ctx.Done()
	klog.V(2).Info("Shutdown workers")
}

func (ec *EtcdController) syncEtcdCluster(key string) error {
	klog.V(4).Info("syncEtcdCluster")
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	c, err := ec.clusterLister.EtcdClusters(namespace).Get(name)
	if err != nil && apierrors.IsNotFound(err) {
		klog.V(4).Infof("%s is not found", key)
		return nil
	} else if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if c.Status.Phase == "" {
		c.Status.Phase = etcdv1alpha1.ClusterPhaseInitializing
		_, err = ec.ecClient.EtcdV1alpha1().EtcdClusters(c.Namespace).Update(c)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	cluster := NewEtcdCluster(c, ec.clusterDomain)
	caSecret, err := ec.setupCA(cluster)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	serverCertSecret, err := ec.setupServerCert(cluster, caSecret)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	_, err = ec.setupClientCert(cluster, caSecret)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	cluster.SetCASecret(caSecret)
	cluster.SetServerCertSecret(serverCertSecret)

	pods, err := ec.getOwnedPods(cluster)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	cluster.SetOwnedPods(pods)

	klog.V(4).Infof("CurrentInternalState: %s", cluster.CurrentInternalState())
	switch cluster.CurrentInternalState() {
	case InternalStateCreatingFirstMember:
		members := cluster.AllMembers()

		if members[0].CreationTimestamp.IsZero() {
			klog.V(4).Infof("Create first member: %s", members[0].Name)
			cluster.SetAnnotationForPod(members[0])
			_, err = ec.client.CoreV1().Pods(cluster.Namespace).Create(members[0])
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			ec.recorder.Event(cluster.EtcdCluster, corev1.EventTypeNormal, "FirstMemberCreated", "The first member has been created")
		} else {
			ec.recorder.Event(cluster.EtcdCluster, corev1.EventTypeNormal, "Waiting", "Waiting for running first member")
			klog.V(4).Info("Waiting for running first member")
		}
	case InternalStateCreatingMembers:
		members := cluster.AllMembers()

		for _, v := range members[1:] {
			if v.CreationTimestamp.IsZero() {
				if err := ec.startMember(cluster, v); err != nil {
					return xerrors.Errorf(": %w", err)
				}
				break
			}

			if cluster.IsPodReady(v) {
				continue
			}

			break
		}
	case InternalStatePreparingUpdate:
		members := cluster.AllMembers()

		var temporaryMember *corev1.Pod
		for _, v := range members {
			if metav1.HasAnnotation(v.ObjectMeta, etcd.AnnotationKeyTemporaryMember) {
				temporaryMember = v
				break
			}
		}
		if temporaryMember == nil {
			return errors.New("all member has been created")
		}

		if temporaryMember.CreationTimestamp.IsZero() {
			if err := ec.startMember(cluster, temporaryMember); err != nil {
				return xerrors.Errorf(": %w", err)
			}
			ec.recorder.Event(cluster.EtcdCluster, corev1.EventTypeNormal, "CreatedTemporaryMember", "The temporary member has been created")
		} else if !cluster.IsPodReady(temporaryMember) {
			ec.recorder.Event(cluster.EtcdCluster, corev1.EventTypeNormal, "Waiting", "Waiting for running temporary member")
			klog.V(4).Info("Waiting for running temporary member")
		}
	case InternalStateUpdatingMember:
		members := cluster.AllMembers()

		var targetMember *corev1.Pod
		for _, p := range members {
			if cluster.ShouldUpdate(p) {
				targetMember = p
				break
			}
		}

		if targetMember == nil {
			break
		}

		clusterReady := true
		for _, p := range members {
			if p.CreationTimestamp.IsZero() {
				continue
			}
			if p.Name == targetMember.Name {
				continue
			}
			if !cluster.IsPodReady(p) {
				clusterReady = false
			}
		}
		if clusterReady {
			if err := ec.updateMember(cluster, targetMember); err != nil {
				return xerrors.Errorf(": %w", err)
			}
		} else {
			klog.V(4).Infof("%s is waiting update", targetMember.Name)
		}
	case InternalStateTeardownUpdating:
		if v := cluster.TemporaryMember(); v != nil {
			if err := ec.deleteMember(cluster, v); err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}

	if err := ec.ensureService(cluster); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := ec.setupDefragmentJob(cluster); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := ec.checkClusterStatus(cluster); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	ec.updateStatus(cluster)
	if !reflect.DeepEqual(cluster.Status, c.Status) {
		klog.V(4).Info("Update EtcdCluster")
		_, err = ec.ecClient.EtcdV1alpha1().EtcdClusters(cluster.Namespace).Update(cluster.EtcdCluster)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (ec *EtcdController) setupCA(cluster *EtcdCluster) (*corev1.Secret, error) {
	caSecret, err := ec.secretLister.Secrets(cluster.Namespace).Get(cluster.CASecretName())
	if err != nil && apierrors.IsNotFound(err) {
		caSecret, err = cluster.CA(nil)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}

		caSecret, err = ec.client.CoreV1().Secrets(cluster.Namespace).Create(caSecret)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		return caSecret, nil
	} else if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return caSecret, nil
}

func (ec *EtcdController) setupServerCert(cluster *EtcdCluster, ca *corev1.Secret) (*corev1.Secret, error) {
	certS, err := ec.secretLister.Secrets(cluster.Namespace).Get(cluster.ServerCertSecretName())
	if err != nil && apierrors.IsNotFound(err) {
		certS, err = cluster.ServerCertSecret(ca)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}

		certS, err = ec.client.CoreV1().Secrets(cluster.Namespace).Create(certS)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		return certS, nil
	} else if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	if cluster.ShouldUpdateServerCertificate(certS.Data[serverCertSecretCertName]) {
		certS, err = cluster.ServerCertSecret(ca)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}

		certS, err = ec.client.CoreV1().Secrets(cluster.Namespace).Update(certS)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		return certS, nil
	}

	return certS, nil
}

func (ec *EtcdController) setupClientCert(cluster *EtcdCluster, ca *corev1.Secret) (*corev1.Secret, error) {
	certS, err := ec.secretLister.Secrets(cluster.Namespace).Get(cluster.ClientCertSecretName())
	if err != nil && apierrors.IsNotFound(err) {
		certS, err = cluster.ClientCertSecret(ca)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}

		certS, err = ec.client.CoreV1().Secrets(cluster.Namespace).Create(certS)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		return certS, nil
	} else if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return certS, nil
}

func (ec *EtcdController) startMember(cluster *EtcdCluster, pod *corev1.Pod) error {
	klog.V(4).Infof("Create %s", pod.Name)

	var endpoints []string
	if ec.runOutsideCluster {
		pods := cluster.AllMembers()
		for _, v := range pods {
			if cluster.IsPodReady(v) {
				forwarder, port, err := ec.portForward(v, 2379)
				if err != nil {
					return xerrors.Errorf(": %w", err)
				}
				defer forwarder.Close()

				endpoints = []string{fmt.Sprintf("https://127.0.0.1:%d", port)}
				klog.V(4).Infof("Port forward to %s", v.Name)
				break
			}
		}
	}

	klog.V(4).Infof("Create etcd client: %v", endpoints)
	eClient, err := cluster.Client(endpoints)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	mList, err := eClient.MemberList(ctx)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	cancelFunc()

	isExistAsMember := false
	for _, v := range mList.Members {
		klog.V(4).Infof("member: %+v", v)
		if len(v.PeerURLs) == 0 {
			klog.Warningf("Found the member that hasn't peer URL. probably a bug of controller")
			continue
		}
		if strings.HasPrefix(v.PeerURLs[0], "https://"+pod.Name) {
			isExistAsMember = true
		}
	}

	if !isExistAsMember {
		klog.V(4).Infof("MemberAdd: %s", pod.Name)
		ctx, cancelFunc := context.WithTimeout(context.Background(), 500*time.Millisecond)
		res, err := eClient.MemberAdd(
			ctx,
			[]string{fmt.Sprintf("https://%s.%s.%s.svc.%s:2380", pod.Name, cluster.ServerDiscoveryServiceName(), cluster.Namespace, cluster.ClusterDomain)},
		)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		cancelFunc()
		klog.V(4).Infof("Added a new member: %+v", res.Member)
	}

	if pod.CreationTimestamp.IsZero() {
		cluster.SetAnnotationForPod(pod)
		_, err = ec.client.CoreV1().Pods(cluster.Namespace).Create(resetPod(pod))
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	ec.recorder.Event(cluster.EtcdCluster, corev1.EventTypeNormal, "MemberCreated", "The new member has been created")
	return nil
}

func (ec *EtcdController) deleteMember(cluster *EtcdCluster, pod *corev1.Pod) error {
	klog.V(4).Infof("Delete a member: %s", pod.Name)

	var endpoints []string
	var forwarder *portforward.PortForwarder
	if ec.runOutsideCluster {
		pods := cluster.AllMembers()
		for _, v := range pods {
			if cluster.IsPodReady(v) && v.Name != pod.Name {
				f, port, err := ec.portForward(v, 2379)
				if err != nil {
					klog.V(4).Infof("Failed open forwarding port: %v", err)
					continue
				}

				endpoints = []string{fmt.Sprintf("https://127.0.0.1:%d", port)}
				forwarder = f
				break
			}
		}
		if forwarder == nil {
			return errors.New("could not port forward to any pod")
		}
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), 3*time.Second)
	eClient, err := cluster.Client(endpoints)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	mList, err := eClient.MemberList(ctx)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	var member *etcdserverpb.Member
	for _, v := range mList.Members {
		if len(v.PeerURLs) == 0 {
			klog.Warningf("The member hasn't any peer url: %d", v.ID)
			continue
		}
		if strings.HasPrefix(v.PeerURLs[0], "https://"+pod.Name) {
			member = v
			break
		}
	}

	if member != nil {
		_, err = eClient.MemberRemove(ctx, member.ID)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		klog.V(4).Infof("Remove a member: %+v", member)
	}

	if err := eClient.Close(); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	cancelFunc()

	if forwarder != nil {
		forwarder.Close()
	}

	if err = ec.client.CoreV1().Pods(cluster.Namespace).Delete(pod.Name, &metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (ec *EtcdController) updateMember(cluster *EtcdCluster, pod *corev1.Pod) error {
	klog.V(4).Infof("Delete and start %s", pod.Name)

	if !pod.CreationTimestamp.IsZero() && cluster.ShouldUpdate(pod) {
		if err := ec.deleteMember(cluster, pod); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return ec.startMember(cluster, pod)
}

func (ec *EtcdController) ensureService(cluster *EtcdCluster) error {
	if err := ec.ensureDiscoveryService(cluster); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := ec.ensureClientService(cluster); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (ec *EtcdController) setupDefragmentJob(cluster *EtcdCluster) error {
	found := true
	cj, err := ec.client.BatchV1beta1().CronJobs(cluster.Namespace).Get(cluster.DefragmentCronJobName(), metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		found = false
	} else if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if cluster.Spec.DefragmentSchedule == "" {
		if found {
			err = ec.client.BatchV1beta1().CronJobs(cluster.Namespace).Delete(cluster.DefragmentCronJobName(), &metav1.DeleteOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			return nil
		}

		return nil
	}

	if found {
		if !reflect.DeepEqual(cj.Spec, cluster.DefragmentCronJob().Spec) {
			_, err := ec.client.BatchV1beta1().CronJobs(cluster.Namespace).Update(cluster.DefragmentCronJob())
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	} else {
		_, err := ec.client.BatchV1beta1().CronJobs(cluster.Namespace).Create(cluster.DefragmentCronJob())
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (ec *EtcdController) ensureDiscoveryService(cluster *EtcdCluster) error {
	_, err := ec.serviceLister.Services(cluster.Namespace).Get(cluster.ServerDiscoveryServiceName())
	if err != nil && apierrors.IsNotFound(err) {
		_, err = ec.client.CoreV1().Services(cluster.Namespace).Create(cluster.DiscoveryService())
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	} else if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (ec *EtcdController) ensureClientService(cluster *EtcdCluster) error {
	_, err := ec.serviceLister.Services(cluster.Namespace).Get(cluster.ClientServiceName())
	if err != nil && apierrors.IsNotFound(err) {
		_, err = ec.client.CoreV1().Services(cluster.Namespace).Create(cluster.ClientService())
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	} else if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (ec *EtcdController) getOwnedPods(cluster *EtcdCluster) ([]*corev1.Pod, error) {
	r, err := labels.NewRequirement(etcd.LabelNameClusterName, selection.Equals, []string{cluster.Name})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	pods, err := ec.podLister.Pods(cluster.Namespace).List(labels.NewSelector().Add(*r))
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return pods, nil
}

func (ec *EtcdController) checkClusterStatus(cluster *EtcdCluster) error {
	etcdPods := make([]*etcdPod, 0)
	forwarder := make([]*portforward.PortForwarder, 0)
	for _, v := range cluster.AllExistMembers() {
		ep := &etcdPod{
			Pod: v,
		}

		if ec.runOutsideCluster {
			if !cluster.IsPodReady(v) {
				continue
			}

			pf, port, err := ec.portForward(v, 2379)
			if err != nil {
				klog.Info(err)
				continue
			}
			forwarder = append(forwarder, pf)
			ep.Endpoint = fmt.Sprintf("https://127.0.0.1:%d", port)
		} else {
			ep.Endpoint = fmt.Sprintf("https://%s:2379", v.Status.PodIP)
		}

		etcdPods = append(etcdPods, ep)
	}
	if len(forwarder) > 0 {
		defer func() {
			klog.V(4).Info("Close all port forwarders")
			for _, v := range forwarder {
				v.Close()
			}
		}()
	}

	endpoints := make([]string, 0)
	for _, v := range etcdPods {
		endpoints = append(endpoints, v.Endpoint)
	}

	etcdClient, err := cluster.Client(endpoints)
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	memberList, err := etcdClient.MemberList(ctx)
	if err != nil {
		return nil
	}
	cancel()

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	for i, v := range etcdPods {
		u, err := url.Parse(v.Endpoint)
		if err != nil {
			continue
		}
		st, err := etcdClient.Status(ctx, u.Host)
		if err != nil {
			klog.Info(err)
			continue
		}
		etcdPods[i].StatusResponse = st
	}
	cancel()

	if err := etcdClient.Close(); err != nil {
		klog.Error(err)
		return xerrors.Errorf(": %w", err)
	}

	cluster.Status.Members = make([]etcdv1alpha1.MemberStatus, 0)
	for _, v := range etcdPods {
		ms := etcdv1alpha1.MemberStatus{
			PodName: v.Name,
		}
		if v.StatusResponse != nil {
			ms.Id = int64(v.StatusResponse.Header.MemberId)
			ms.Version = "v" + v.StatusResponse.Version

			for _, m := range memberList.Members {
				if m.ID == v.StatusResponse.Header.MemberId {
					ms.Name = m.Name
					break
				}
			}

			if v.StatusResponse.Leader == v.StatusResponse.Header.MemberId {
				ms.Leader = true
			}
		}

		cluster.Status.Members = append(cluster.Status.Members, ms)
	}

	sort.Slice(cluster.Status.Members, func(i, j int) bool {
		return cluster.Status.Members[i].Name < cluster.Status.Members[j].Name
	})

	return nil
}

func (ec *EtcdController) updateStatus(cluster *EtcdCluster) {
	cluster.Status.Phase = cluster.CurrentPhase()
	switch cluster.Status.Phase {
	case etcdv1alpha1.ClusterPhaseRunning, etcdv1alpha1.ClusterPhaseUpdating:
		if !cluster.Status.Ready {
			now := metav1.Now()
			cluster.Status.LastReadyTransitionTime = &now
		}
		cluster.Status.Ready = true
	default:
		cluster.Status.Ready = false
	}
	klog.V(4).Infof("Phase: %v", cluster.Status.Phase)

	cluster.Status.ClientCertSecretName = cluster.ClientCertSecretName()
	cluster.Status.ClientEndpoint = fmt.Sprintf("https://%s.%s.svc.%s:2379", cluster.ClientServiceName(), cluster.Namespace, cluster.ClusterDomain)

	s := labels.SelectorFromSet(map[string]string{
		etcd.LabelNameClusterName: cluster.Name,
		etcd.LabelNameRole:        "defragment",
	})
	jobList, err := ec.client.BatchV1().Jobs(cluster.Namespace).List(metav1.ListOptions{LabelSelector: s.String()})
	if err != nil {
		return
	}

	for _, v := range jobList.Items {
		if v.Status.Succeeded != 1 {
			continue
		}

		if cluster.Status.LastDefragmentTime.Before(v.Status.CompletionTime) {
			cluster.Status.LastDefragmentTime = v.Status.CompletionTime
		}
		if cluster.Status.LastDefragmentTime.IsZero() {
			cluster.Status.LastDefragmentTime = v.Status.CompletionTime
		}
	}
}

func (ec *EtcdController) portForward(pod *corev1.Pod, port int) (*portforward.PortForwarder, uint16, error) {
	if pod.Status.Phase != corev1.PodRunning {
		return nil, 0, errors.New("pod is not running yet")
	}

	req := ec.client.CoreV1().RESTClient().Post().Resource("pods").Namespace(pod.Namespace).Name(pod.Name).SubResource("portforward")
	transport, upgrader, err := spdy.RoundTripperFor(ec.config)
	if err != nil {
		return nil, 0, xerrors.Errorf(": %w", err)
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, req.URL())

	readyCh := make(chan struct{})
	pf, err := portforward.New(dialer, []string{fmt.Sprintf(":%d", port)}, context.Background().Done(), readyCh, nil, nil)
	if err != nil {
		return nil, 0, xerrors.Errorf(": %w", err)
	}
	go func() {
		err := pf.ForwardPorts()
		if err != nil {
			switch v := err.(type) {
			case *apierrors.StatusError:
				klog.Info(v)
			}
			klog.Error(err)
		}
	}()

	select {
	case <-readyCh:
	case <-time.After(5 * time.Second):
		return nil, 0, errors.New("timed out")
	}

	ports, err := pf.GetPorts()
	if err != nil {
		return nil, 0, xerrors.Errorf(": %w", err)
	}

	return pf, ports[0].Local, nil
}

func (ec *EtcdController) worker() {
	defer klog.V(4).Info("Finish worker")

	for ec.processNextItem() {
	}
}

func (ec *EtcdController) processNextItem() bool {
	defer klog.V(4).Info("Finish processNextItem")

	obj, shutdown := ec.queue.Get()
	if shutdown {
		return false
	}
	klog.V(4).Infof("Get next queue: %s", obj)

	err := func(obj interface{}) error {
		defer ec.queue.Done(obj)

		err := ec.syncEtcdCluster(obj.(string))
		if err != nil {
			ec.queue.AddRateLimited(obj)
			return err
		}

		ec.queue.Forget(obj)
		return nil
	}(obj)
	if err != nil {
		klog.Infof("%+v", err)
		return true
	}

	return true
}

func (ec *EtcdController) enqueue(cluster *etcdv1alpha1.EtcdCluster) {
	if key, err := cache.MetaNamespaceKeyFunc(cluster); err != nil {
		return
	} else {
		ec.queue.Add(key)
	}
}

func (ec *EtcdController) addEtcdCluster(obj interface{}) {
	cluster := obj.(*etcdv1alpha1.EtcdCluster)

	ec.enqueue(cluster)
}

func (ec *EtcdController) updateEtcdCluster(old, cur interface{}) {
	oldCluster := old.(*etcdv1alpha1.EtcdCluster)
	curCluster := cur.(*etcdv1alpha1.EtcdCluster)

	if oldCluster.UID != curCluster.UID {
		if key, err := cache.MetaNamespaceKeyFunc(oldCluster); err != nil {
			return
		} else {
			ec.deleteEtcdCluster(cache.DeletedFinalStateUnknown{Key: key, Obj: oldCluster})
		}
	}

	ec.enqueue(curCluster)
}

func (ec *EtcdController) deleteEtcdCluster(obj interface{}) {
	cluster, ok := obj.(*etcdv1alpha1.EtcdCluster)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}
		cluster, ok = tombstone.Obj.(*etcdv1alpha1.EtcdCluster)
		if !ok {
			return
		}
	}

	ec.enqueue(cluster)
}

func (ec *EtcdController) updatePod(old, cur interface{}) {
	oldPod := old.(*corev1.Pod)
	curPod := cur.(*corev1.Pod)

	if oldPod.UID != curPod.UID {
		if key, err := cache.MetaNamespaceKeyFunc(oldPod); err != nil {
			return
		} else {
			ec.deletePod(cache.DeletedFinalStateUnknown{Key: key, Obj: oldPod})
		}
	}

	if v, ok := curPod.Labels[etcd.LabelNameClusterName]; !ok || v == "" {
		klog.V(5).Infof("Pod doesn't have label: %v", curPod.Labels)
		return
	}

	klog.V(4).Infof("Enqueue: %s/%s for update pod", curPod.Namespace, curPod.Labels[etcd.LabelNameClusterName])
	ec.queue.Add(curPod.Namespace + "/" + curPod.Labels[etcd.LabelNameClusterName])
}

func (ec *EtcdController) deletePod(obj interface{}) {
	klog.Info("Delete pod")
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			klog.V(4).Info("Object is not DeletedFinalStateUnknown")
			return
		}
		pod, ok = tombstone.Obj.(*corev1.Pod)
		if !ok {
			klog.V(4).Info("Object is DeletedFinalStateUnknown but Obj is not Pod")
			return
		}
	}
	if v, ok := pod.Labels[etcd.LabelNameClusterName]; !ok || v == "" {
		klog.V(5).Infof("Pod doesn't have label: %v", pod.Labels)
		return
	}

	klog.V(4).Infof("Enqueue: %s/%s for delete pod", pod.Namespace, pod.Labels[etcd.LabelNameClusterName])
	ec.queue.Add(pod.Namespace + "/" + pod.Labels[etcd.LabelNameClusterName])
}
