package controllers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/minio/minio-go/v6"
	"go.etcd.io/etcd/v3/clientv3"
	"go.etcd.io/etcd/v3/clientv3/snapshot"
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
	"github.com/f110/lagrangian-proxy/pkg/logger"
)

const (
	defaultEtcdVersion = "v3.4.0"
)

type EtcdController struct {
	schema.GroupVersionKind

	config            *rest.Config
	coreClient        kubernetes.Interface
	client            clientset.Interface
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

	// for testing hack
	etcdClientMockOpt *MockOption
	transport         http.RoundTripper
}

func NewEtcdController(
	sharedInformerFactory informers.SharedInformerFactory,
	coreSharedInformerFactory kubeinformers.SharedInformerFactory,
	coreClient kubernetes.Interface,
	client clientset.Interface,
	cfg *rest.Config,
	clusterDomain string,
	runOutsideCluster bool,
	transport http.RoundTripper,
	mockOpt *MockOption,
) (*EtcdController, error) {
	podInformer := coreSharedInformerFactory.Core().V1().Pods()
	serviceInformer := coreSharedInformerFactory.Core().V1().Services()
	secretInformer := coreSharedInformerFactory.Core().V1().Secrets()

	etcdClusterInformer := sharedInformerFactory.Etcd().V1alpha1().EtcdClusters()

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: coreClient.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: "etcd-controller"})

	c := &EtcdController{
		config:              cfg,
		client:              client,
		coreClient:          coreClient,
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
		transport:           transport,
		etcdClientMockOpt:   mockOpt,
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

type internalStateHandleFunc func(cluster *EtcdCluster) error

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
	if c.Status.Phase == "" || c.Status.Phase == etcdv1alpha1.ClusterPhasePending {
		c.Status.Phase = etcdv1alpha1.ClusterPhaseInitializing
		_, err = ec.client.EtcdV1alpha1().EtcdClusters(c.Namespace).UpdateStatus(c)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	cluster := NewEtcdCluster(c, ec.clusterDomain, ec.etcdClientMockOpt)
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

	var handler internalStateHandleFunc
	klog.V(4).Infof("CurrentInternalState: %s", cluster.CurrentInternalState())
	switch cluster.CurrentInternalState() {
	case InternalStateCreatingFirstMember:
		handler = ec.stateCreatingFirstMember
	case InternalStateCreatingMembers:
		handler = ec.stateCreatingMembers
	case InternalStateRepair:
		handler = ec.stateRepair
	case InternalStatePreparingUpdate:
		handler = ec.statePreparingUpdate
	case InternalStateUpdatingMember:
		handler = ec.stateUpdatingMember
	case InternalStateTeardownUpdating:
		handler = ec.stateTeardownUpdating
	case InternalStateRestore:
		handler = ec.stateRestore
	case InternalStateRunning:
	default:
		return xerrors.Errorf("Unknown internal state: %s", cluster.CurrentInternalState())
	}

	if handler != nil {
		if err := handler(cluster); err != nil {
			return xerrors.Errorf(": %w", err)
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

	if cluster.Status.Phase == etcdv1alpha1.ClusterPhaseRunning && ec.shouldBackup(cluster) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
		err := ec.doBackup(ctx, cluster)
		if err != nil {
			cluster.Status.Backup.Succeeded = false
			ec.recorder.Event(cluster.EtcdCluster, corev1.EventTypeWarning, "BackupFailure", fmt.Sprintf("Failed backup: %v", err))
		} else {
			cluster.Status.Backup.Succeeded = true
			cluster.Status.Backup.LastSucceededTime = cluster.Status.Backup.History[0].ExecuteTime
			ec.recorder.Event(cluster.EtcdCluster, corev1.EventTypeNormal, "BackupSuccess", fmt.Sprintf("Backup succeeded"))
		}

		err = ec.doRotateBackup(ctx, cluster)
		if err != nil {
			ec.recorder.Event(cluster.EtcdCluster, corev1.EventTypeWarning, "RotateBackupFailure", fmt.Sprintf("Failed rotate backup: %v", err))
		}
		cancelFunc()

		ec.updateBackupStatus(cluster)
	}

	if !reflect.DeepEqual(cluster.Status, c.Status) {
		klog.V(4).Info("Update EtcdCluster")
		_, err = ec.client.EtcdV1alpha1().EtcdClusters(cluster.Namespace).UpdateStatus(cluster.EtcdCluster)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (ec *EtcdController) stateCreatingFirstMember(cluster *EtcdCluster) error {
	if cluster.Status.RestoreFrom == "" {
		return ec.createNewCluster(cluster)
	} else {
		return ec.createNewClusterWithBackup(cluster)
	}
}

func (ec *EtcdController) createNewCluster(cluster *EtcdCluster) error {
	members := cluster.AllMembers()

	if members[0].CreationTimestamp.IsZero() {
		klog.V(4).Infof("Create first member: %s", members[0].Name)
		cluster.SetAnnotationForPod(members[0])
		_, err := ec.coreClient.CoreV1().Pods(cluster.Namespace).Create(members[0])
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		ec.recorder.Event(cluster.EtcdCluster, corev1.EventTypeNormal, "FirstMemberCreated", "The first member has been created")
	} else {
		ec.recorder.Event(cluster.EtcdCluster, corev1.EventTypeNormal, "Waiting", "Waiting for running first member")
		klog.V(4).Info("Waiting for running first member")
	}

	return nil
}

func (ec *EtcdController) createNewClusterWithBackup(cluster *EtcdCluster) error {
	members := cluster.AllMembers()
	if members[0].CreationTimestamp.IsZero() {
		klog.V(4).Infof("Create first member: %s", members[0].Name)
		cluster.SetAnnotationForPod(members[0])
		receiverContainer := corev1.Container{
			Name:         "receive-backup-file",
			Image:        "busybox:latest",
			Command:      []string{"/bin/sh", "-c", "nc -l -p 2900 > /data/backup"},
			VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data"}},
		}
		members[0].Spec.InitContainers = append([]corev1.Container{receiverContainer}, members[0].Spec.InitContainers...)

		_, err := ec.coreClient.CoreV1().Pods(cluster.Namespace).Create(members[0])
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		return nil
	}

	readyReceiver := false
	for _, v := range members[0].Status.InitContainerStatuses {
		if v.Name == "receive-backup-file" {
			if v.State.Running != nil {
				readyReceiver = true
				break
			}
		}
	}
	if readyReceiver {
		if err := ec.sendBackupToContainer(cluster, members[0], cluster.Status.RestoreFrom); err != nil {
			return xerrors.Errorf(": %w", err)
		}

		cluster.Status.RestoreFrom = ""
		return nil
	}

	ec.recorder.Event(cluster.EtcdCluster, corev1.EventTypeNormal, "Waiting", "Waiting for running first member")
	klog.V(4).Info("Waiting for running first member")

	return nil
}

func (ec *EtcdController) stateCreatingMembers(cluster *EtcdCluster) error {
	members := cluster.AllMembers()

	for _, v := range members {
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

	return nil
}

func (ec *EtcdController) stateRepair(cluster *EtcdCluster) error {
	members := cluster.AllMembers()

	var targetMember *corev1.Pod
	for _, v := range members {
		if cluster.NeedRepair(v) {
			targetMember = v
			break

		}
	}

	if targetMember != nil {
		canDeleteMember := true
		for _, v := range members {
			if targetMember.UID == v.UID {
				continue
			}

			if v.Status.Phase != corev1.PodRunning {
				canDeleteMember = false
			}
		}

		if !canDeleteMember {
			ec.recorder.Event(cluster.EtcdCluster, corev1.EventTypeWarning, "CantRepairMember", "another member(s) is also not ready.")
			return nil
		}

		// At this time, we will transition to CreatingMembers
		// if we delete the member which is needs repair.
		if err := ec.deleteMember(cluster, targetMember); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (ec *EtcdController) statePreparingUpdate(cluster *EtcdCluster) error {
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

	return nil
}

func (ec *EtcdController) stateUpdatingMember(cluster *EtcdCluster) error {
	members := cluster.AllMembers()

	var targetMember *corev1.Pod
	for _, p := range members {
		if cluster.ShouldUpdate(p) {
			targetMember = p
			break
		}
	}

	if targetMember == nil {
		return nil
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

	return nil
}

func (ec *EtcdController) stateTeardownUpdating(cluster *EtcdCluster) error {
	if v := cluster.TemporaryMember(); v != nil {
		if err := ec.deleteMember(cluster, v); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (ec *EtcdController) stateRestore(cluster *EtcdCluster) error {
	for _, v := range cluster.Status.Backup.History {
		if v.Succeeded {
			cluster.Status.RestoreFrom = v.Path
			break
		}
	}
	_, err := ec.client.EtcdV1alpha1().EtcdClusters(cluster.Namespace).UpdateStatus(cluster.EtcdCluster)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	members := cluster.AllExistMembers()

	for _, v := range members {
		if err := ec.coreClient.CoreV1().Pods(v.Namespace).Delete(v.Name, &metav1.DeleteOptions{}); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	cluster.Status.LastReadyTransitionTime = nil
	return nil
}

func (ec *EtcdController) sendBackupToContainer(cluster *EtcdCluster, pod *corev1.Pod, backupPath string) error {
	klog.V(4).Infof("Send to a backup file to %s: %s", pod.Name, backupPath)
	backupFile, forwarder, err := ec.getBackupFile(cluster, backupPath)
	if forwarder != nil {
		defer forwarder.Close()
	}
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	endpoint := fmt.Sprintf("%s:%d", pod.Status.PodIP, 2900)
	if ec.runOutsideCluster {
		forwarder, localPort, err := ec.portForward(pod, 2900)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		defer forwarder.Close()

		endpoint = fmt.Sprintf("127.0.0.1:%d", localPort)
	}

	conn, err := net.Dial("tcp", endpoint)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if _, err := io.Copy(conn, backupFile); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := conn.Close(); err != nil {
		return xerrors.Errorf(": %w", err)
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

		caSecret, err = ec.coreClient.CoreV1().Secrets(cluster.Namespace).Create(caSecret)
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

		certS, err = ec.coreClient.CoreV1().Secrets(cluster.Namespace).Create(certS)
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

		certS, err = ec.coreClient.CoreV1().Secrets(cluster.Namespace).Update(certS)
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

		certS, err = ec.coreClient.CoreV1().Secrets(cluster.Namespace).Create(certS)
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

	eClient, forwarder, err := ec.etcdClient(cluster)
	if forwarder != nil {
		defer forwarder.Close()
	}
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

	if err := eClient.Close(); err != nil && !errors.Is(err, context.Canceled) {
		return xerrors.Errorf(": %w", err)
	}

	if pod.CreationTimestamp.IsZero() {
		cluster.SetAnnotationForPod(pod)
		_, err = ec.coreClient.CoreV1().Pods(cluster.Namespace).Create(resetPod(pod))
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	ec.recorder.Event(cluster.EtcdCluster, corev1.EventTypeNormal, "MemberCreated", "The new member has been created")
	return nil
}

func (ec *EtcdController) deleteMember(cluster *EtcdCluster, pod *corev1.Pod) error {
	klog.V(4).Infof("Delete a member: %s", pod.Name)

	ctx, cancelFunc := context.WithTimeout(context.Background(), 3*time.Second)
	eClient, forwarder, err := ec.etcdClient(cluster)
	if forwarder != nil {
		defer forwarder.Close()
	}
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

	if err := eClient.Close(); err != nil && !errors.Is(err, context.Canceled) {
		return xerrors.Errorf(": %w", err)
	}
	cancelFunc()

	if forwarder != nil {
		forwarder.Close()
	}

	if err = ec.coreClient.CoreV1().Pods(cluster.Namespace).Delete(pod.Name, &metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
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
	cj, err := ec.coreClient.BatchV1beta1().CronJobs(cluster.Namespace).Get(cluster.DefragmentCronJobName(), metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		found = false
	} else if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if cluster.Spec.DefragmentSchedule == "" {
		if found {
			err = ec.coreClient.BatchV1beta1().CronJobs(cluster.Namespace).Delete(cluster.DefragmentCronJobName(), &metav1.DeleteOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			return nil
		}

		return nil
	}

	if found {
		if !reflect.DeepEqual(cj.Spec, cluster.DefragmentCronJob().Spec) {
			_, err := ec.coreClient.BatchV1beta1().CronJobs(cluster.Namespace).Update(cluster.DefragmentCronJob())
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	} else {
		_, err := ec.coreClient.BatchV1beta1().CronJobs(cluster.Namespace).Create(cluster.DefragmentCronJob())
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (ec *EtcdController) ensureDiscoveryService(cluster *EtcdCluster) error {
	_, err := ec.serviceLister.Services(cluster.Namespace).Get(cluster.ServerDiscoveryServiceName())
	if err != nil && apierrors.IsNotFound(err) {
		_, err = ec.coreClient.CoreV1().Services(cluster.Namespace).Create(cluster.DiscoveryService())
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
		_, err = ec.coreClient.CoreV1().Services(cluster.Namespace).Create(cluster.ClientService())
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

	if err := etcdClient.Close(); err != nil && !errors.Is(err, context.Canceled) {
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
	case etcdv1alpha1.ClusterPhaseRunning, etcdv1alpha1.ClusterPhaseUpdating, etcdv1alpha1.ClusterPhaseDegrading:
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
	jobList, err := ec.coreClient.BatchV1().Jobs(cluster.Namespace).List(metav1.ListOptions{LabelSelector: s.String()})
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

func (ec *EtcdController) updateBackupStatus(cluster *EtcdCluster) {
	succeededCount := 0
	lastIndex := 0
	for i, v := range cluster.Status.Backup.History {
		if v.Succeeded {
			succeededCount++
			lastIndex = i
		}
		if succeededCount == cluster.Spec.Backup.MaxBackups {
			break
		}
	}
	if succeededCount == cluster.Spec.Backup.MaxBackups && lastIndex+1 < len(cluster.Status.Backup.History) {
		cluster.Status.Backup.History = cluster.Status.Backup.History[:lastIndex+1]
	}
}

func (ec *EtcdController) shouldBackup(cluster *EtcdCluster) bool {
	if cluster.Spec.Backup == nil {
		return false
	}
	if cluster.Status.Backup == nil {
		return true
	}
	if cluster.Status.Backup.LastSucceededTime.IsZero() {
		return true
	}
	if cluster.Status.Backup.LastSucceededTime.Add(time.Duration(cluster.Spec.Backup.IntervalInSecond) * time.Second).Before(time.Now()) {
		return true
	}

	return false
}

func (ec *EtcdController) doBackup(ctx context.Context, cluster *EtcdCluster) error {
	now := metav1.Now()
	backupStatus := &etcdv1alpha1.BackupStatusHistory{ExecuteTime: &now}
	defer func() {
		if cluster.Status.Backup == nil {
			cluster.Status.Backup = &etcdv1alpha1.BackupStatus{}
		}
		cluster.Status.Backup.History = append([]etcdv1alpha1.BackupStatusHistory{*backupStatus}, cluster.Status.Backup.History...)
	}()

	client, forwarder, err := ec.etcdClient(cluster)
	if forwarder != nil {
		defer forwarder.Close()
	}
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	tmpFile, err := ioutil.TempFile("", "")
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	defer os.Remove(tmpFile.Name())

	data, err := client.Snapshot(ctx)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	dataSize, err := io.Copy(tmpFile, data)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := data.Close(); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	sm := snapshot.NewV3(logger.Log)
	dbStatus, err := sm.Status(tmpFile.Name())
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	backupStatus.EtcdRevision = dbStatus.Revision

	f, err := os.Open(tmpFile.Name())
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := ec.storeBackupFile(ctx, cluster, backupStatus, f, dataSize, now); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	backupStatus.Succeeded = true
	return nil
}

func (ec *EtcdController) storeBackupFile(ctx context.Context, cluster *EtcdCluster, backupStatus *etcdv1alpha1.BackupStatusHistory, data io.Reader, dataSize int64, t metav1.Time) error {
	switch {
	case cluster.Spec.Backup.Storage.MinIO != nil:
		spec := cluster.Spec.Backup.Storage.MinIO

		mc, forwarder, err := ec.minioClient(spec)
		if forwarder != nil {
			defer forwarder.Close()
		}
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		filename := fmt.Sprintf("%s_%d", cluster.Name, t.Unix())
		path := spec.Path
		if path[0] == '/' {
			path = path[1:]
		}
		backupStatus.Path = filepath.Join(path, filename)
		_, err = mc.PutObjectWithContext(ctx, spec.Bucket, filepath.Join(path, filename), data, dataSize, minio.PutObjectOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		return nil
	case cluster.Spec.Backup.Storage.S3 != nil:
		spec := cluster.Spec.Backup.Storage.S3
		credential, err := ec.secretLister.Secrets(spec.CredentialSecretNamespace).Get(spec.CredentialSecretName)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		accessKey := credential.Data[spec.AccessKeyIDKey]
		secretAccessKey := credential.Data[spec.SecretAccessKeyKey]
		mc, err := minio.New(spec.Endpoint, string(accessKey), string(secretAccessKey), spec.Insecure)
		if err != nil {
			return err
		}
		filename := fmt.Sprintf("%s_%d", cluster.Name, t.Unix())
		backupStatus.Path = filepath.Join(spec.Path, filename)
		_, err = mc.PutObjectWithContext(ctx, spec.Bucket, filepath.Join(spec.Path, filename), data, dataSize, minio.PutObjectOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		return nil
	default:
		return xerrors.New("Not configured a storage")
	}
}

func (ec *EtcdController) doRotateBackup(ctx context.Context, cluster *EtcdCluster) error {
	if cluster.Spec.Backup.MaxBackups == 0 {
		// In this case, we shouldn't rotate backup files.
		return nil
	}

	switch {
	case cluster.Spec.Backup.Storage.MinIO != nil:
		spec := cluster.Spec.Backup.Storage.MinIO

		mc, forwarder, err := ec.minioClient(spec)
		if forwarder != nil {
			defer forwarder.Close()
		}
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		listCh := mc.ListObjectsV2(spec.Bucket, spec.Path+"/", false, ctx.Done())
		backupFiles := make([]string, 0)
		for obj := range listCh {
			if obj.Err != nil {
				return xerrors.Errorf(": %w", obj.Err)
			}
			if strings.HasPrefix(obj.Key, filepath.Join(spec.Path, cluster.Name)) {
				backupFiles = append(backupFiles, obj.Key)
			}
		}
		klog.V(4).Infof("Backup files: %v", backupFiles)
		if len(backupFiles) <= cluster.Spec.Backup.MaxBackups {
			return nil
		}
		sort.Strings(backupFiles)
		sort.Sort(sort.Reverse(sort.StringSlice(backupFiles)))
		purgeTargets := backupFiles[cluster.Spec.Backup.MaxBackups:]
		for _, v := range purgeTargets {
			if err := mc.RemoveObject(spec.Bucket, v); err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}

		return nil
	default:
		return xerrors.New("Not configured a storage")
	}
}

func (ec *EtcdController) getBackupFile(cluster *EtcdCluster, path string) (io.ReadCloser, *portforward.PortForwarder, error) {
	switch {
	case cluster.Spec.Backup.Storage.MinIO != nil:
		spec := cluster.Spec.Backup.Storage.MinIO

		mc, forwarder, err := ec.minioClient(spec)
		if err != nil {
			return nil, forwarder, xerrors.Errorf(": %w", err)
		}

		obj, err := mc.GetObject(spec.Bucket, path, minio.GetObjectOptions{})
		if err != nil {
			return nil, forwarder, xerrors.Errorf(": %w", err)
		}

		return obj, forwarder, nil
	default:
		return nil, nil, errors.New("not supported")
	}
}

func (ec *EtcdController) minioClient(spec *etcdv1alpha1.BackupStorageMinIOSpec) (*minio.Client, *portforward.PortForwarder, error) {
	svc, err := ec.serviceLister.Services(spec.ServiceSelector.Namespace).Get(spec.ServiceSelector.Name)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %w", err)
	}

	instanceEndpoint := fmt.Sprintf("%s.%s.svc:%d", svc.Name, svc.Namespace, svc.Spec.Ports[0].Port)
	var forwarder *portforward.PortForwarder
	if ec.runOutsideCluster {
		selector := labels.SelectorFromSet(svc.Spec.Selector)
		pods, err := ec.podLister.List(selector)
		if err != nil {
			return nil, nil, xerrors.Errorf(": %w", err)
		}
		var targetPod *corev1.Pod
		for _, v := range pods {
			if v.Status.Phase == corev1.PodRunning {
				targetPod = v
				break
			}
		}
		if targetPod == nil {
			return nil, nil, xerrors.New("all pods are not running")
		}

		f, port, err := ec.portForward(targetPod, int(svc.Spec.Ports[0].Port))
		if err != nil {
			return nil, nil, xerrors.Errorf(": %w", err)
		}
		forwarder = f

		instanceEndpoint = fmt.Sprintf("127.0.0.1:%d", port)
	}

	credential, err := ec.secretLister.Secrets(spec.CredentialSelector.Namespace).Get(spec.CredentialSelector.Name)
	if err != nil {
		return nil, forwarder, xerrors.Errorf(": %w", err)
	}

	accessKey := credential.Data[spec.CredentialSelector.AccessKeyIDKey]
	secretAccessKey := credential.Data[spec.CredentialSelector.SecretAccessKeyKey]
	mc, err := minio.New(instanceEndpoint, string(accessKey), string(secretAccessKey), spec.Secure)
	if err != nil {
		return nil, forwarder, xerrors.Errorf(": %w", err)
	}
	mc.SetCustomTransport(ec.transport)

	return mc, forwarder, nil
}

func (ec *EtcdController) etcdClient(cluster *EtcdCluster) (*clientv3.Client, *portforward.PortForwarder, error) {
	var endpoints []string
	var forwarder *portforward.PortForwarder
	if ec.runOutsideCluster {
		pods := cluster.AllMembers()
		for _, v := range pods {
			if cluster.IsPodReady(v) {
				f, port, err := ec.portForward(v, 2379)
				if err != nil {
					return nil, nil, xerrors.Errorf(": %w", err)
				}
				forwarder = f

				endpoints = []string{fmt.Sprintf("https://127.0.0.1:%d", port)}
				klog.V(4).Infof("Port forward to %s", v.Name)
				break
			}
		}
	}

	client, err := cluster.Client(endpoints)
	if err != nil {
		return nil, forwarder, xerrors.Errorf(": %w", err)
	}

	return client, forwarder, nil
}

func (ec *EtcdController) portForward(pod *corev1.Pod, port int) (*portforward.PortForwarder, uint16, error) {
	req := ec.coreClient.CoreV1().RESTClient().Post().Resource("pods").Namespace(pod.Namespace).Name(pod.Name).SubResource("portforward")
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
	for _, v := range curPod.OwnerReferences {
		ec.queue.Add(curPod.Namespace + "/" + v.Name)
	}
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
	for _, v := range pod.OwnerReferences {
		ec.queue.Add(pod.Namespace + "/" + v.Name)
	}
}
