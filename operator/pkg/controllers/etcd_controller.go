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

	"cloud.google.com/go/storage"
	"github.com/minio/minio-go/v6"
	"go.etcd.io/etcd/v3/clientv3"
	"go.etcd.io/etcd/v3/clientv3/snapshot"
	"go.etcd.io/etcd/v3/etcdserver/etcdserverpb"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

	"go.f110.dev/heimdallr/operator/pkg/api/etcd"
	etcdv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha1"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
	"go.f110.dev/heimdallr/operator/pkg/controllers/controllerbase"
	informers "go.f110.dev/heimdallr/operator/pkg/informers/externalversions"
	etcdlisters "go.f110.dev/heimdallr/operator/pkg/listers/etcd/v1alpha1"
	"go.f110.dev/heimdallr/pkg/logger"
)

const (
	defaultEtcdVersion = "v3.4.0"
)

type EtcdController struct {
	*controllerbase.Controller

	config            *rest.Config
	coreClient        kubernetes.Interface
	client            clientset.Interface
	clusterDomain     string
	runOutsideCluster bool

	etcdClusterInformer cache.SharedIndexInformer
	clusterLister       etcdlisters.EtcdClusterLister
	clusterListerSynced cache.InformerSynced
	podInformer         cache.SharedIndexInformer
	podLister           listers.PodLister
	podListerSynced     cache.InformerSynced
	serviceLister       listers.ServiceLister
	serviceListerSynced cache.InformerSynced
	secretLister        listers.SecretLister
	secretListerSynced  cache.InformerSynced
	pvcLister           listers.PersistentVolumeClaimLister
	pvcListerSynced     cache.InformerSynced

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
	pvcInformer := coreSharedInformerFactory.Core().V1().PersistentVolumeClaims()

	etcdClusterInformer := sharedInformerFactory.Etcd().V1alpha1().EtcdClusters()

	c := &EtcdController{
		config:              cfg,
		client:              client,
		coreClient:          coreClient,
		clusterDomain:       clusterDomain,
		runOutsideCluster:   runOutsideCluster,
		etcdClusterInformer: etcdClusterInformer.Informer(),
		clusterLister:       etcdClusterInformer.Lister(),
		clusterListerSynced: etcdClusterInformer.Informer().HasSynced,
		podInformer:         podInformer.Informer(),
		podLister:           podInformer.Lister(),
		podListerSynced:     podInformer.Informer().HasSynced,
		serviceLister:       serviceInformer.Lister(),
		serviceListerSynced: serviceInformer.Informer().HasSynced,
		secretLister:        secretInformer.Lister(),
		secretListerSynced:  secretInformer.Informer().HasSynced,
		pvcLister:           pvcInformer.Lister(),
		pvcListerSynced:     pvcInformer.Informer().HasSynced,
		transport:           transport,
		etcdClientMockOpt:   mockOpt,
	}

	c.Controller = controllerbase.NewController(c, coreClient)
	return c, nil
}

func (ec *EtcdController) Name() string {
	return "etcd-controller"
}

func (ec *EtcdController) Finalizers() []string {
	return []string{}
}

func (ec *EtcdController) ListerSynced() []cache.InformerSynced {
	return []cache.InformerSynced{
		ec.clusterListerSynced,
		ec.podListerSynced,
		ec.serviceListerSynced,
		ec.secretListerSynced,
		ec.pvcListerSynced,
	}
}

func (ec *EtcdController) EventSources() []cache.SharedIndexInformer {
	return []cache.SharedIndexInformer{
		ec.etcdClusterInformer,
		ec.podInformer,
	}
}

func (ec *EtcdController) ConvertToKeys() controllerbase.ObjectToKeyConverter {
	return func(obj interface{}) (keys []string, err error) {
		switch obj.(type) {
		case *etcdv1alpha1.EtcdCluster:
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err != nil {
				return nil, err
			}
			return []string{key}, nil
		case *corev1.Pod:
			pod := obj.(*corev1.Pod)
			if v, ok := pod.Labels[etcd.LabelNameClusterName]; !ok || v == "" {
				return nil, nil
			}

			ec.Log().Debug("Enqueue pod", zap.String("key", pod.Namespace+"/"+pod.Labels[etcd.LabelNameClusterName]))
			keys = make([]string, len(pod.OwnerReferences))
			for i, v := range pod.OwnerReferences {
				keys[i] = fmt.Sprintf("%s/%s", pod.Namespace, v.Name)
			}
			return keys, nil
		default:
			ec.Log().Info("Unhandled object type", zap.String("type", reflect.TypeOf(obj).String()))
			return nil, nil
		}
	}
}

func (ec *EtcdController) GetObject(key string) (interface{}, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	c, err := ec.clusterLister.EtcdClusters(namespace).Get(name)
	if err != nil && apierrors.IsNotFound(err) {
		ec.Log().Debug("EtcdCluster is not found", zap.String("key", key))
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return c, nil
}

func (ec *EtcdController) UpdateObject(ctx context.Context, obj interface{}) error {
	etcdCluster, ok := obj.(*etcdv1alpha1.EtcdCluster)
	if !ok {
		return nil
	}

	_, err := ec.client.EtcdV1alpha1().EtcdClusters(etcdCluster.Namespace).Update(ctx, etcdCluster, metav1.UpdateOptions{})
	return err
}

type internalStateHandleFunc func(ctx context.Context, cluster *EtcdCluster) error

func (ec *EtcdController) Reconcile(ctx context.Context, obj interface{}) error {
	ec.Log().Debug("syncEtcdCluster")
	c := obj.(*etcdv1alpha1.EtcdCluster)

	if c.Status.Phase == "" || c.Status.Phase == etcdv1alpha1.ClusterPhasePending {
		c.Status.Phase = etcdv1alpha1.ClusterPhaseInitializing
		_, err := ec.client.EtcdV1alpha1().EtcdClusters(c.Namespace).UpdateStatus(ctx, c, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	cluster := NewEtcdCluster(c, ec.clusterDomain, ec.Log(), ec.etcdClientMockOpt)
	caSecret, err := ec.setupCA(ctx, cluster)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	serverCertSecret, err := ec.setupServerCert(ctx, cluster, caSecret)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	_, err = ec.setupClientCert(ctx, cluster, caSecret)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	cluster.SetCASecret(caSecret)
	cluster.SetServerCertSecret(serverCertSecret)
	if err := cluster.GetOwnedPods(ec.podLister, ec.pvcLister); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	var handler internalStateHandleFunc
	ec.Log().Debug("Execute handler", zap.String("internalState", string(cluster.CurrentInternalState())))
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
		handler = ec.stateRunning
	default:
		return xerrors.Errorf("Unknown internal state: %s", cluster.CurrentInternalState())
	}

	if handler != nil {
		if err := handler(ctx, cluster); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if err := ec.ensureService(ctx, cluster); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if err := ec.checkClusterStatus(ctx, cluster); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	ec.updateStatus(ctx, cluster)

	if cluster.Status.Phase == etcdv1alpha1.ClusterPhaseRunning && ec.shouldBackup(cluster) {
		err := ec.doBackup(ctx, cluster)
		if err != nil {
			cluster.Status.Backup.Succeeded = false
			ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeWarning, "BackupFailure", fmt.Sprintf("Failed backup: %v", err))
		} else {
			cluster.Status.Backup.Succeeded = true
			cluster.Status.Backup.LastSucceededTime = cluster.Status.Backup.History[0].ExecuteTime
			ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeNormal, "BackupSuccess", fmt.Sprintf("Backup succeeded"))
		}

		err = ec.doRotateBackup(ctx, cluster)
		if err != nil {
			ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeWarning, "RotateBackupFailure", fmt.Sprintf("Failed rotate backup: %v", err))
		}

		ec.updateBackupStatus(cluster)
	}

	if !reflect.DeepEqual(cluster.Status, c.Status) {
		ec.Log().Debug("Update EtcdCluster")
		_, err = ec.client.EtcdV1alpha1().EtcdClusters(cluster.Namespace).UpdateStatus(ctx, cluster.EtcdCluster, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (ec *EtcdController) Finalize(_ context.Context, _ interface{}) error {
	return nil
}

func (ec *EtcdController) stateCreatingFirstMember(ctx context.Context, cluster *EtcdCluster) error {
	if cluster.Status.RestoreFrom == "" {
		if err := ec.createNewCluster(ctx, cluster); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	} else {
		if err := ec.createNewClusterWithBackup(ctx, cluster); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (ec *EtcdController) createNewCluster(ctx context.Context, cluster *EtcdCluster) error {
	members := cluster.AllMembers()

	if members[0].Pod.CreationTimestamp.IsZero() {
		ec.Log().Debug("Create first member", zap.String("name", members[0].Pod.Name))
		if err := ec.startMember(ctx, cluster, members[0]); err != nil {
			return xerrors.Errorf(": %w", err)
		}
		ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeNormal, "FirstMemberCreated", "The first member has been created")
	} else {
		ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeNormal, "Waiting", "Waiting for running first member")
		ec.Log().Debug("Waiting for running first member", zap.String("name", members[0].Pod.Name))
	}

	return nil
}

func (ec *EtcdController) createNewClusterWithBackup(ctx context.Context, cluster *EtcdCluster) error {
	members := cluster.AllMembers()
	if members[0].Pod.CreationTimestamp.IsZero() {
		ec.Log().Debug("Create first member", zap.String("name", members[0].Pod.Name))
		cluster.SetAnnotationForPod(members[0].Pod)
		receiverContainer := corev1.Container{
			Name:         "receive-backup-file",
			Image:        "busybox:latest",
			Command:      []string{"/bin/sh", "-c", "nc -l -p 2900 > /data/backup"},
			VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/data"}},
		}
		members[0].Pod.Spec.InitContainers = append(
			members[0].Pod.Spec.InitContainers,
			receiverContainer,
		)

		_, err := ec.coreClient.CoreV1().Pods(cluster.Namespace).Create(ctx, members[0].Pod, metav1.CreateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		return nil
	}

	readyReceiver := false
	for _, v := range members[0].Pod.Status.InitContainerStatuses {
		if v.Name == "receive-backup-file" {
			if v.State.Running != nil {
				readyReceiver = true
				break
			}
		}
	}
	if readyReceiver {
		if err := ec.sendBackupToContainer(cluster, members[0].Pod, cluster.Status.RestoreFrom); err != nil {
			return xerrors.Errorf(": %w", err)
		}

		cluster.Status.RestoreFrom = ""
		return nil
	}

	ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeNormal, "Waiting", "Waiting for running first member")
	ec.Log().Debug("Waiting for running first member", zap.String("name", members[0].Pod.Name))

	return nil
}

func (ec *EtcdController) stateCreatingMembers(ctx context.Context, cluster *EtcdCluster) error {
	members := cluster.AllMembers()

	ctx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()

	var targetMember *EtcdMember
	for _, v := range members {
		if !cluster.IsPodReady(v.Pod) && !v.Pod.CreationTimestamp.IsZero() {
			break
		}

		if v.Pod.CreationTimestamp.IsZero() {
			targetMember = v
			break
		}
	}

	if targetMember != nil {
		if err := ec.startMember(ctx, cluster, targetMember); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (ec *EtcdController) stateRepair(ctx context.Context, cluster *EtcdCluster) error {
	members := cluster.AllMembers()

	var targetMember *EtcdMember
	for _, v := range members {
		if cluster.NeedRepair(v.Pod) {
			targetMember = v
			break
		}
	}

	if targetMember != nil {
		canDeleteMember := true
		for _, v := range members {
			if targetMember.Pod.UID == v.Pod.UID {
				continue
			}

			if v.Pod.Status.Phase != corev1.PodRunning {
				canDeleteMember = false
			}
		}

		if !canDeleteMember {
			ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeWarning, "CantRepairMember", "another member(s) is also not ready.")
			return nil
		}

		// At this time, we will transition to CreatingMembers
		// if we delete the member which is needs repair.
		if err := ec.deleteMember(ctx, cluster, targetMember); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (ec *EtcdController) stateRunning(ctx context.Context, cluster *EtcdCluster) error {
	if err := ec.setupDefragmentJob(ctx, cluster); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (ec *EtcdController) statePreparingUpdate(ctx context.Context, cluster *EtcdCluster) error {
	members := cluster.AllMembers()

	var temporaryMember *EtcdMember
	for _, v := range members {
		if metav1.HasAnnotation(v.Pod.ObjectMeta, etcd.AnnotationKeyTemporaryMember) {
			temporaryMember = v
			break
		}
	}
	if temporaryMember == nil {
		return errors.New("all member has been created")
	}

	if temporaryMember.Pod.CreationTimestamp.IsZero() {
		ctx, cancelFunc := context.WithTimeout(ctx, 5*time.Second)
		defer cancelFunc()

		if err := ec.startMember(ctx, cluster, temporaryMember); err != nil {
			return xerrors.Errorf(": %w", err)
		}
		ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeNormal, "CreatedTemporaryMember", "The temporary member has been created")
	} else if !cluster.IsPodReady(temporaryMember.Pod) {
		ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeNormal, "Waiting", "Waiting for running temporary member")
		ec.Log().Debug("Waiting for running temporary member", zap.String("name", temporaryMember.Pod.Name))
	}

	return nil
}

func (ec *EtcdController) stateUpdatingMember(ctx context.Context, cluster *EtcdCluster) error {
	members := cluster.AllMembers()

	var targetMember *EtcdMember
	for _, p := range members {
		if p.OldVersion {
			targetMember = p
			break
		}

		if p.Pod.CreationTimestamp.IsZero() {
			targetMember = p
			break
		}
	}
	if targetMember == nil {
		for _, p := range members {
			if cluster.ShouldUpdate(p.Pod) {
				targetMember = p
				break
			}
		}
	}
	if targetMember == nil {
		return nil
	}

	clusterReady := true
	readyMembers := 0
	for _, p := range members {
		if p.Pod.CreationTimestamp.IsZero() {
			continue
		}
		if p.Pod.Name == targetMember.Pod.Name {
			continue
		}
		if !cluster.IsPodReady(p.Pod) {
			clusterReady = false
		}
		readyMembers++
	}
	if readyMembers < cluster.Spec.Members {
		for _, v := range members {
			if v.Pod.CreationTimestamp.IsZero() {
				targetMember = v
				break
			}
		}
	}

	if clusterReady {
		if targetMember.Pod.CreationTimestamp.IsZero() {
			ctx, cancelFunc := context.WithTimeout(ctx, 5*time.Second)
			defer cancelFunc()
			return ec.startMember(ctx, cluster, targetMember)
		}

		if err := ec.updateMember(ctx, cluster, targetMember); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	} else {
		ec.Log().Debug("Waiting update", zap.String("name", targetMember.Pod.Name))
	}

	return nil
}

func (ec *EtcdController) stateTeardownUpdating(ctx context.Context, cluster *EtcdCluster) error {
	if v := cluster.TemporaryMember(); v != nil {
		if err := ec.deleteMember(ctx, cluster, v); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (ec *EtcdController) stateRestore(ctx context.Context, cluster *EtcdCluster) error {
	for _, v := range cluster.Status.Backup.History {
		if v.Succeeded {
			cluster.Status.RestoreFrom = v.Path
			break
		}
	}
	_, err := ec.client.EtcdV1alpha1().EtcdClusters(cluster.Namespace).UpdateStatus(ctx, cluster.EtcdCluster, metav1.UpdateOptions{})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	members := cluster.AllExistMembers()

	for _, v := range members {
		if err := ec.coreClient.CoreV1().Pods(v.Namespace).Delete(ctx, v.Name, metav1.DeleteOptions{}); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	cluster.Status.LastReadyTransitionTime = nil
	return nil
}

func (ec *EtcdController) sendBackupToContainer(cluster *EtcdCluster, pod *corev1.Pod, backupPath string) error {
	ec.Log().Debug("Send to a backup file", zap.String("pod.name", pod.Name), zap.String("path", backupPath))
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

func (ec *EtcdController) setupCA(ctx context.Context, cluster *EtcdCluster) (*corev1.Secret, error) {
	caSecret, err := ec.secretLister.Secrets(cluster.Namespace).Get(cluster.CASecretName())
	if err != nil && apierrors.IsNotFound(err) {
		caSecret, err = cluster.CA(nil)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}

		caSecret, err = ec.coreClient.CoreV1().Secrets(cluster.Namespace).Create(ctx, caSecret, metav1.CreateOptions{})
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		return caSecret, nil
	} else if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return caSecret, nil
}

func (ec *EtcdController) setupServerCert(ctx context.Context, cluster *EtcdCluster, ca *corev1.Secret) (*corev1.Secret, error) {
	certS, err := ec.secretLister.Secrets(cluster.Namespace).Get(cluster.ServerCertSecretName())
	if err != nil && apierrors.IsNotFound(err) {
		certS, err = cluster.ServerCertSecret(ca)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}

		certS, err = ec.coreClient.CoreV1().Secrets(cluster.Namespace).Create(ctx, certS, metav1.CreateOptions{})
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

		certS, err = ec.coreClient.CoreV1().Secrets(cluster.Namespace).Update(ctx, certS, metav1.UpdateOptions{})
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		return certS, nil
	}

	return certS, nil
}

func (ec *EtcdController) setupClientCert(ctx context.Context, cluster *EtcdCluster, ca *corev1.Secret) (*corev1.Secret, error) {
	certS, err := ec.secretLister.Secrets(cluster.Namespace).Get(cluster.ClientCertSecretName())
	if err != nil && apierrors.IsNotFound(err) {
		certS, err = cluster.ClientCertSecret(ca)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}

		certS, err = ec.coreClient.CoreV1().Secrets(cluster.Namespace).Create(ctx, certS, metav1.CreateOptions{})
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		return certS, nil
	} else if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return certS, nil
}

func (ec *EtcdController) startMember(ctx context.Context, cluster *EtcdCluster, member *EtcdMember) error {
	ec.Log().Debug("Start member", zap.String("pod.name", member.Pod.Name))

	if member.PersistentVolumeClaim != nil && member.PersistentVolumeClaim.CreationTimestamp.IsZero() {
		_, err := ec.coreClient.CoreV1().PersistentVolumeClaims(cluster.Namespace).Create(ctx, member.PersistentVolumeClaim, metav1.CreateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	if member.Pod.CreationTimestamp.IsZero() {
		cluster.SetAnnotationForPod(member.Pod)
		_, err := ec.coreClient.CoreV1().Pods(cluster.Namespace).Create(ctx, resetPod(member.Pod), metav1.CreateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeNormal, "MemberCreated", "The new member has been created")
	return nil
}

func (ec *EtcdController) deleteMember(ctx context.Context, cluster *EtcdCluster, member *EtcdMember) error {
	ec.Log().Debug("Delete the member", zap.String("pod.name", member.Pod.Name))

	eClient, forwarder, err := ec.etcdClient(cluster)
	if forwarder != nil {
		defer forwarder.Close()
	}
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	defer func() {
		if eClient != nil {
			eClient.Close()
		}
	}()
	err = eClient.WithTimeout(ctx, 3*time.Second, func(ctx context.Context) error {
		mList, err := eClient.MemberList(ctx)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		var memberStatus *etcdserverpb.Member
		for _, v := range mList.Members {
			ec.Log().Debug("Found the member", zap.String("name", v.Name), zap.Strings("peerURLs", v.PeerURLs))
			if len(v.PeerURLs) == 0 {
				ec.Log().Warn("The member hasn't any peer url", zap.Uint64("id", v.ID), zap.String("name", v.Name))
				continue
			}
			if strings.HasPrefix(v.PeerURLs[0], "https://"+strings.Replace(member.Pod.Status.PodIP, ".", "-", -1)) {
				memberStatus = v
			}
		}

		if memberStatus != nil {
			_, err = eClient.MemberRemove(ctx, memberStatus.ID)
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			ec.Log().Debug("Remove the member from cluster", zap.String("name", memberStatus.Name), zap.Strings("peerURLs", memberStatus.PeerURLs))
		}

		if err := eClient.Close(); err != nil && !errors.Is(err, context.Canceled) {
			return xerrors.Errorf(": %w", err)
		}

		return nil
	})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if forwarder != nil {
		forwarder.Close()
	}

	if err = ec.coreClient.CoreV1().Pods(cluster.Namespace).Delete(ctx, member.Pod.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (ec *EtcdController) updateMember(ctx context.Context, cluster *EtcdCluster, member *EtcdMember) error {
	ec.Log().Debug("Delete and start", zap.String("pod.name", member.Pod.Name))

	if !member.Pod.CreationTimestamp.IsZero() && cluster.ShouldUpdate(member.Pod) {
		if err := ec.deleteMember(ctx, cluster, member); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (ec *EtcdController) ensureService(ctx context.Context, cluster *EtcdCluster) error {
	if err := ec.ensureDiscoveryService(ctx, cluster); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := ec.ensureClientService(ctx, cluster); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (ec *EtcdController) setupDefragmentJob(ctx context.Context, cluster *EtcdCluster) error {
	found := true
	cj, err := ec.coreClient.BatchV1beta1().CronJobs(cluster.Namespace).Get(ctx, cluster.DefragmentCronJobName(), metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		found = false
	} else if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	if cluster.Spec.DefragmentSchedule == "" {
		if found {
			err = ec.coreClient.BatchV1beta1().CronJobs(cluster.Namespace).Delete(ctx, cluster.DefragmentCronJobName(), metav1.DeleteOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			return nil
		}

		return nil
	}

	if found {
		if !reflect.DeepEqual(cj.Spec, cluster.DefragmentCronJob().Spec) {
			_, err := ec.coreClient.BatchV1beta1().CronJobs(cluster.Namespace).Update(ctx, cluster.DefragmentCronJob(), metav1.UpdateOptions{})
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	} else {
		_, err := ec.coreClient.BatchV1beta1().CronJobs(cluster.Namespace).Create(ctx, cluster.DefragmentCronJob(), metav1.CreateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func (ec *EtcdController) ensureDiscoveryService(ctx context.Context, cluster *EtcdCluster) error {
	_, err := ec.serviceLister.Services(cluster.Namespace).Get(cluster.ServerDiscoveryServiceName())
	if err != nil && apierrors.IsNotFound(err) {
		_, err = ec.coreClient.CoreV1().Services(cluster.Namespace).Create(ctx, cluster.DiscoveryService(), metav1.CreateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	} else if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (ec *EtcdController) ensureClientService(ctx context.Context, cluster *EtcdCluster) error {
	_, err := ec.serviceLister.Services(cluster.Namespace).Get(cluster.ClientServiceName())
	if err != nil && apierrors.IsNotFound(err) {
		_, err = ec.coreClient.CoreV1().Services(cluster.Namespace).Create(ctx, cluster.ClientService(), metav1.CreateOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	} else if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (ec *EtcdController) checkClusterStatus(ctx context.Context, cluster *EtcdCluster) error {
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

			pf, port, err := ec.portForward(v, EtcdClientPort)
			if err != nil {
				ec.Log().Info("Failed port forward", zap.Error(err))
				continue
			}
			forwarder = append(forwarder, pf)
			ep.Endpoint = fmt.Sprintf("https://127.0.0.1:%d", port)
		} else {
			ep.Endpoint = fmt.Sprintf("https://%s:%d", v.Status.PodIP, EtcdClientPort)
		}

		etcdPods = append(etcdPods, ep)
	}
	if len(forwarder) > 0 {
		defer func() {
			ec.Log().Debug("Close all port forwarders")
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
	defer func() {
		if err := etcdClient.Close(); err != nil && !errors.Is(err, context.Canceled) {
			ec.Log().Info("Failed close etcd client", zap.Error(err))
		}
	}()

	mlCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	memberList, err := etcdClient.MemberList(mlCtx)
	if err != nil {
		return nil
	}
	cancel()

	sCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	for i, v := range etcdPods {
		u, err := url.Parse(v.Endpoint)
		if err != nil {
			continue
		}
		st, err := etcdClient.Status(sCtx, u.Host)
		if err != nil {
			ec.Log().Info("Failed get status", zap.Error(err))
			continue
		}
		etcdPods[i].StatusResponse = st
	}
	cancel()

	cluster.Status.Members = make([]etcdv1alpha1.MemberStatus, 0)
	for _, m := range memberList.Members {
		ms := etcdv1alpha1.MemberStatus{
			Name: m.Name,
		}

		for _, p := range etcdPods {
			if p.StatusResponse == nil {
				continue
			}
			if m.ID != p.StatusResponse.Header.MemberId {
				continue
			}

			ms.Id = int64(p.StatusResponse.Header.MemberId)
			ms.Version = "v" + p.StatusResponse.Version
			if p.StatusResponse.Leader == p.StatusResponse.Header.MemberId {
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

func (ec *EtcdController) updateStatus(ctx context.Context, cluster *EtcdCluster) {
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
	ec.Log().Debug("Current Phase", zap.String("phase", string(cluster.Status.Phase)), zap.String("cluster.name", cluster.Name))

	cluster.Status.ClientCertSecretName = cluster.ClientCertSecretName()
	cluster.Status.ClientEndpoint = fmt.Sprintf("https://%s.%s.svc.%s:%d", cluster.ClientServiceName(), cluster.Namespace, cluster.ClusterDomain, EtcdClientPort)

	s := labels.SelectorFromSet(map[string]string{
		etcd.LabelNameClusterName: cluster.Name,
		etcd.LabelNameRole:        "defragment",
	})
	jobList, err := ec.coreClient.BatchV1().Jobs(cluster.Namespace).List(ctx, metav1.ListOptions{LabelSelector: s.String()})
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
	defer func() {
		if client != nil {
			client.Close()
		}
	}()

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
	case cluster.Spec.Backup.Storage.GCS != nil:
		spec := cluster.Spec.Backup.Storage.GCS
		namespace := spec.CredentialSelector.Namespace
		if namespace == "" {
			namespace = cluster.Namespace
		}
		credential, err := ec.secretLister.Secrets(namespace).Get(spec.CredentialSelector.Name)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		b, ok := credential.Data[spec.CredentialSelector.ServiceAccountJSONKey]
		if !ok {
			return xerrors.Errorf("%s is not found", spec.CredentialSelector.ServiceAccountJSONKey)
		}

		client, err := storage.NewClient(ctx, option.WithCredentialsJSON(b))
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		filename := fmt.Sprintf("%s_%d", cluster.Name, t.Unix())
		obj := client.Bucket(spec.Bucket).Object(filepath.Join(spec.Path, filename))
		w := obj.NewWriter(ctx)
		if _, err := io.Copy(w, data); err != nil {
			return xerrors.Errorf(": %w", err)
		}
		if err := w.Close(); err != nil {
			return xerrors.Errorf(": %w", err)
		}
		backupStatus.Path = filepath.Join(spec.Path, filename)

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
		ec.Log().Debug("Backup files", zap.Strings("files", backupFiles))
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
	case cluster.Spec.Backup.Storage.GCS != nil:
		spec := cluster.Spec.Backup.Storage.GCS
		namespace := spec.CredentialSelector.Namespace
		if namespace == "" {
			namespace = cluster.Namespace
		}
		credential, err := ec.secretLister.Secrets(namespace).Get(spec.CredentialSelector.Name)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		b, ok := credential.Data[spec.CredentialSelector.ServiceAccountJSONKey]
		if !ok {
			return xerrors.Errorf("%s is not found", spec.CredentialSelector.ServiceAccountJSONKey)
		}
		client, err := storage.NewClient(ctx, option.WithCredentialsJSON(b))
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		bh := client.Bucket(spec.Bucket)

		backupFiles := make([]string, 0)
		iter := bh.Objects(ctx, &storage.Query{Prefix: spec.Path})
		for {
			attr, err := iter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			backupFiles = append(backupFiles, attr.Name)
		}
		ec.Log().Debug("Backup files", zap.Strings("files", backupFiles))
		if len(backupFiles) <= cluster.Spec.Backup.MaxBackups {
			return nil
		}
		sort.Strings(backupFiles)
		sort.Sort(sort.Reverse(sort.StringSlice(backupFiles)))
		purgeTargets := backupFiles[cluster.Spec.Backup.MaxBackups:]
		for _, v := range purgeTargets {
			ec.Log().Debug("Delete backup file", zap.String("target", v))
			if err := bh.Object(v).Delete(ctx); err != nil {
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

type etcdv3Client struct {
	*clientv3.Client
}

func (c *etcdv3Client) WithTimeout(ctx context.Context, timeout time.Duration, f func(ctx context.Context) error) error {
	eCtx, cancelFunc := context.WithTimeout(ctx, timeout)
	defer cancelFunc()

	return f(eCtx)
}

func (ec *EtcdController) etcdClient(cluster *EtcdCluster) (*etcdv3Client, *portforward.PortForwarder, error) {
	var endpoints []string
	var forwarder *portforward.PortForwarder
	if ec.runOutsideCluster {
		pods := cluster.AllMembers()
		for _, v := range pods {
			if cluster.IsPodReady(v.Pod) {
				f, port, err := ec.portForward(v.Pod, EtcdClientPort)
				if err != nil {
					return nil, nil, xerrors.Errorf(": %w", err)
				}
				forwarder = f

				endpoints = []string{fmt.Sprintf("https://127.0.0.1:%d", port)}
				ec.Log().Debug("Port forward", zap.String("to", v.Pod.Name))
				break
			}
		}
	}

	client, err := cluster.Client(endpoints)
	if err != nil {
		return nil, forwarder, xerrors.Errorf(": %w", err)
	}

	return &etcdv3Client{Client: client}, forwarder, nil
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
				ec.Log().Info("Failed get forwarded ports", zap.Error(v))
			}
			ec.Log().Info("Failed get forwarded ports", zap.Error(err))
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
