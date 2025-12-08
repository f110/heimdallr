package controllers

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.etcd.io/etcd/api/v3/etcdserverpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/etcdutl/v3/snapshot"
	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"
	"go.f110.dev/kubeproto/go/k8sclient"
	"go.f110.dev/xerrors"
	"go.uber.org/zap"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/portforward"

	"go.f110.dev/heimdallr/pkg/k8s/api/etcd"
	"go.f110.dev/heimdallr/pkg/k8s/api/etcdv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/client"
	"go.f110.dev/heimdallr/pkg/k8s/controllers/controllerbase"
	"go.f110.dev/heimdallr/pkg/logger"
)

const (
	defaultEtcdVersion = "v3.5.1"
)

type EtcdController struct {
	*controllerbase.Controller

	config            *rest.Config
	coreClient        *k8sclient.Set
	client            *client.EtcdV1alpha2
	clusterDomain     string
	runOutsideCluster bool

	etcdClusterInformer  cache.SharedIndexInformer
	clusterLister        *client.EtcdV1alpha2EtcdClusterLister
	clusterListerSynced  cache.InformerSynced
	podInformer          cache.SharedIndexInformer
	podLister            *k8sclient.CoreV1PodLister
	podListerSynced      cache.InformerSynced
	serviceLister        *k8sclient.CoreV1ServiceLister
	serviceListerSynced  cache.InformerSynced
	secretLister         *k8sclient.CoreV1SecretLister
	secretListerSynced   cache.InformerSynced
	pvcLister            *k8sclient.CoreV1PersistentVolumeClaimLister
	pvcListerSynced      cache.InformerSynced
	serviceAccountLister *k8sclient.CoreV1ServiceAccountLister
	serviceAccountSynced cache.InformerSynced

	// for testing hack
	etcdClientMockOpt *MockOption
	transport         http.RoundTripper
}

func NewEtcdController(
	sharedInformerFactory *client.InformerFactory,
	coreSharedInformerFactory *k8sclient.InformerFactory,
	coreClient *k8sclient.Set,
	etcdClient *client.EtcdV1alpha2,
	k8sClient kubernetes.Interface,
	cfg *rest.Config,
	clusterDomain string,
	runOutsideCluster bool,
	transport http.RoundTripper,
	mockOpt *MockOption,
) (*EtcdController, error) {
	corev1Informer := k8sclient.NewCoreV1Informer(coreSharedInformerFactory.Cache(), coreClient.CoreV1, metav1.NamespaceAll, 30*time.Second)
	etcdClusterInformer := client.NewEtcdV1alpha2Informer(sharedInformerFactory.Cache(), etcdClient, metav1.NamespaceAll, 30*time.Second)

	c := &EtcdController{
		config:               cfg,
		client:               etcdClient,
		coreClient:           coreClient,
		clusterDomain:        clusterDomain,
		runOutsideCluster:    runOutsideCluster,
		etcdClusterInformer:  etcdClusterInformer.EtcdClusterInformer(),
		clusterLister:        etcdClusterInformer.EtcdClusterLister(),
		clusterListerSynced:  etcdClusterInformer.EtcdClusterInformer().HasSynced,
		podInformer:          corev1Informer.PodInformer(),
		podLister:            corev1Informer.PodLister(),
		podListerSynced:      corev1Informer.PodInformer().HasSynced,
		serviceLister:        corev1Informer.ServiceLister(),
		serviceListerSynced:  corev1Informer.ServiceInformer().HasSynced,
		secretLister:         corev1Informer.SecretLister(),
		secretListerSynced:   corev1Informer.SecretInformer().HasSynced,
		pvcLister:            corev1Informer.PersistentVolumeClaimLister(),
		pvcListerSynced:      corev1Informer.PersistentVolumeClaimInformer().HasSynced,
		serviceAccountLister: corev1Informer.ServiceAccountLister(),
		serviceAccountSynced: corev1Informer.ServiceAccountInformer().HasSynced,
		transport:            transport,
		etcdClientMockOpt:    mockOpt,
	}

	c.Controller = controllerbase.NewController(c, k8sClient)
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
		ec.serviceAccountSynced,
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
		case *etcdv1alpha2.EtcdCluster:
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

			ec.Log(nil).Debug("Enqueue pod", zap.String("key", pod.Namespace+"/"+pod.Labels[etcd.LabelNameClusterName]))
			keys = make([]string, len(pod.OwnerReferences))
			for i, v := range pod.OwnerReferences {
				keys[i] = fmt.Sprintf("%s/%s", pod.Namespace, v.Name)
			}
			return keys, nil
		default:
			ec.Log(nil).Info("Unhandled object type", zap.String("type", reflect.TypeOf(obj).String()))
			return nil, nil
		}
	}
}

func (ec *EtcdController) GetObject(key string) (interface{}, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	c, err := ec.clusterLister.Get(namespace, name)
	if err != nil && apierrors.IsNotFound(err) {
		ec.Log(nil).Debug("EtcdCluster is not found", zap.String("key", key))
		return nil, nil
	} else if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return c, nil
}

func (ec *EtcdController) UpdateObject(ctx context.Context, obj interface{}) error {
	etcdCluster, ok := obj.(*etcdv1alpha2.EtcdCluster)
	if !ok {
		return nil
	}

	_, err := ec.client.UpdateEtcdCluster(ctx, etcdCluster, metav1.UpdateOptions{})
	return err
}

type internalStateHandleFunc func(ctx context.Context, cluster *EtcdCluster) error

func (ec *EtcdController) Reconcile(ctx context.Context, obj interface{}) error {
	c := obj.(*etcdv1alpha2.EtcdCluster)
	ec.Log(ctx).Debug("syncEtcdCluster", zap.String("namespace", c.Namespace), zap.String("name", c.Name))

	if c.Status.Phase == "" || c.Status.Phase == etcdv1alpha2.EtcdClusterPhasePending {
		c.Status.Phase = etcdv1alpha2.EtcdClusterPhaseInitializing
		updatedEC, err := ec.client.UpdateStatusEtcdCluster(ctx, c, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
		c = updatedEC
	}

	cluster := NewEtcdCluster(c, ec.clusterDomain, ec.Log(ctx), ec.etcdClientMockOpt)
	cluster.Init(ec.secretLister)
	if err := ec.setupCA(ctx, cluster); err != nil {
		return err
	}
	if err := ec.setupServerCert(ctx, cluster); err != nil {
		return err
	}
	if err := ec.setupClientCert(ctx, cluster); err != nil {
		return err
	}
	if err := cluster.GetOwnedPods(ec.podLister, ec.pvcLister); err != nil {
		return err
	}
	if err := ec.ensureServiceAccount(ctx, cluster); err != nil {
		return err
	}

	var handler internalStateHandleFunc
	ec.Log(ctx).Debug("Execute handler", zap.String("internalState", string(cluster.CurrentInternalState())))
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
		return xerrors.NewfWithStack("Unknown internal state: %s", cluster.CurrentInternalState())
	}

	if handler != nil {
		if err := handler(ctx, cluster); err != nil {
			return err
		}
	}

	for _, v := range cluster.AllExistMembers() {
		if metav1.HasAnnotation(v.ObjectMeta, etcd.PodAnnotationKeyRunningAt) {
			continue
		}

		if v.Status.Phase != corev1.PodPhaseRunning {
			continue
		}
		initFinished := true
		for _, cont := range v.Status.InitContainerStatuses {
			if cont.State.Terminated == nil {
				initFinished = false
				break
			}
			if cont.State.Terminated.Reason != "Completed" {
				initFinished = false
				break
			}
			if cont.State.Terminated.FinishedAt.IsZero() {
				initFinished = false
				break
			}
		}
		if !initFinished {
			continue
		}

		if len(v.Status.ContainerStatuses) != len(v.Spec.Containers) {
			continue
		}
		running := true
		for _, cont := range v.Status.ContainerStatuses {
			if !cont.Started {
				running = false
				break
			}
			if cont.Started != true || cont.Ready != true {
				running = false
				break
			}
		}
		if !running {
			continue
		}

		now := ctx.Value(controllerbase.TimeKey{}).(time.Time)
		metav1.SetMetadataAnnotation(&v.ObjectMeta, etcd.PodAnnotationKeyRunningAt, now.Format(time.RFC3339))
		ec.Log(ctx).Debug("Add annotation",
			zap.String("pod.name", v.Name),
			zap.String("key", etcd.PodAnnotationKeyRunningAt),
			zap.String("value", v.Annotations[etcd.PodAnnotationKeyRunningAt]),
		)
		p, err := ec.coreClient.CoreV1.UpdatePod(ctx, v, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
		p.ObjectMeta.DeepCopyInto(&v.ObjectMeta)
	}

	if err := ec.ensureService(ctx, cluster); err != nil {
		return err
	}

	if err := ec.checkClusterStatus(ctx, cluster); err != nil {
		return err
	}

	ec.updateStatus(ctx, cluster)

	if cluster.Status.Phase == etcdv1alpha2.EtcdClusterPhaseRunning && ec.shouldBackup(cluster) {
		err := ec.doBackup(ctx, cluster)
		if err != nil {
			ec.Log(ctx).Warn("Failed backup", zap.Error(err))
			cluster.Status.Backup.Succeeded = false
			ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeWarning, "BackupFailure", fmt.Sprintf("Failed backup: %v", err))
		} else {
			cluster.Status.Backup.Succeeded = true
			cluster.Status.Backup.LastSucceededTime = cluster.Status.Backup.History[0].ExecuteTime
			ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeNormal, "BackupSuccess", fmt.Sprintf("Backup succeeded"))
		}

		err = ec.doRotateBackup(ctx, cluster)
		if err != nil {
			ec.Log(ctx).Warn("Failed rotate backup", zap.Error(err))
			ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeWarning, "RotateBackupFailure", fmt.Sprintf("Failed rotate backup: %v", err))
		}

		ec.updateBackupStatus(cluster)
	}

	if !reflect.DeepEqual(cluster.Status, c.Status) {
		ec.Log(ctx).Debug("Update EtcdCluster")
		_, err := ec.client.UpdateStatusEtcdCluster(ctx, cluster.EtcdCluster, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
	}

	return nil
}

func (ec *EtcdController) Finalize(_ context.Context, _ interface{}) error {
	return nil
}

func (ec *EtcdController) stateCreatingFirstMember(ctx context.Context, cluster *EtcdCluster) error {
	if cluster.Status.Restored != nil && !cluster.Status.Restored.Completed {
		if err := ec.createNewClusterWithBackup(ctx, cluster); err != nil {
			return err
		}
	} else {
		if err := ec.createNewCluster(ctx, cluster); err != nil {
			return err
		}
	}

	return nil
}

func (ec *EtcdController) createNewCluster(ctx context.Context, cluster *EtcdCluster) error {
	members := cluster.AllMembers()

	if members[0].Pod.CreationTimestamp.IsZero() {
		ec.Log(ctx).Debug("Create first member", zap.String("name", members[0].Pod.Name))
		if err := ec.startMember(ctx, cluster, members[0]); err != nil {
			return err
		}
		ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeNormal, "FirstMemberCreated", "The first member has been created")
	} else {
		ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeNormal, "Waiting", "Waiting for running first member")
		ec.Log(ctx).Debug("Waiting for running first member", zap.String("name", members[0].Pod.Name))
	}

	return nil
}

func (ec *EtcdController) createNewClusterWithBackup(ctx context.Context, cluster *EtcdCluster) error {
	members := cluster.AllMembers()
	if members[0].Pod.CreationTimestamp.IsZero() {
		ec.Log(ctx).Debug("Create first member", zap.String("name", members[0].Pod.Name))
		cluster.SetAnnotationForPod(members[0].Pod)
		cluster.InjectRestoreContainer(members[0].Pod)

		_, err := ec.coreClient.CoreV1.CreatePod(ctx, members[0].Pod, metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
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
		if err := ec.sendBackupToContainer(ctx, cluster, members[0].Pod, cluster.Status.Restored.Path); err != nil {
			return err
		}

		return nil
	}

	ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeNormal, "Waiting", "Waiting for running first member")
	ec.Log(ctx).Debug("Waiting for running first member", zap.String("name", members[0].Pod.Name))

	return nil
}

func (ec *EtcdController) stateCreatingMembers(ctx context.Context, cluster *EtcdCluster) error {
	members := cluster.AllMembers()

	ctx, cancelFunc := context.WithTimeout(ctx, 10*time.Second)
	defer cancelFunc()

	var targetMember *EtcdMember
	for _, v := range members {
		ec.Log(ctx).Debug(
			"candidate pod",
			zap.String("name", v.Pod.Name),
			zap.String("phase", string(v.Pod.Status.Phase)),
		)
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
			return err
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
			if v.Pod.CreationTimestamp.IsZero() {
				continue
			}

			if v.Pod.Status.Phase != corev1.PodPhaseRunning {
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
			return err
		}
	}

	return nil
}

func (ec *EtcdController) stateRunning(ctx context.Context, cluster *EtcdCluster) error {
	if err := ec.setupDefragmentJob(ctx, cluster); err != nil {
		return err
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
			return err
		}
		ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeNormal, "CreatedTemporaryMember", "The temporary member has been created")
	} else if !cluster.IsPodReady(temporaryMember.Pod) {
		ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeNormal, "Waiting", "Waiting for running temporary member")
		ec.Log(ctx).Debug("Waiting for running temporary member", zap.String("name", temporaryMember.Pod.Name))
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
			return err
		}
	} else {
		ec.Log(ctx).Debug("Waiting update", zap.String("name", targetMember.Pod.Name))
	}

	return nil
}

func (ec *EtcdController) stateTeardownUpdating(ctx context.Context, cluster *EtcdCluster) error {
	if v := cluster.TemporaryMember(); v != nil {
		if err := ec.deleteMember(ctx, cluster, v); err != nil {
			return err
		}
	}

	return nil
}

func (ec *EtcdController) stateRestore(ctx context.Context, cluster *EtcdCluster) error {
	for _, v := range cluster.Status.Backup.History {
		if v.Succeeded {
			cluster.Status.Restored = &etcdv1alpha2.RestoredStatus{
				Path:       v.Path,
				BackupTime: v.ExecuteTime,
			}
			break
		}
	}

	members := cluster.AllExistMembers()

	for _, v := range members {
		ec.Log(ctx).Debug("Delete pod", zap.String("name", v.Name))
		if err := ec.coreClient.CoreV1.DeletePod(ctx, v.Namespace, v.Name, metav1.DeleteOptions{}); err != nil {
			return xerrors.WithStack(err)
		}
	}

	cluster.Status.LastReadyTransitionTime = nil
	return nil
}

func (ec *EtcdController) sendBackupToContainer(ctx context.Context, cluster *EtcdCluster, pod *corev1.Pod, backupPath string) error {
	ec.Log(ctx).Debug("Send to a backup file", zap.String("pod.name", pod.Name), zap.String("path", backupPath))
	backupFile, forwarder, err := ec.getBackupFile(ctx, cluster, backupPath)
	if forwarder != nil {
		defer forwarder.Close()
	}
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s:%d", pod.Status.PodIP, 2900)
	if ec.runOutsideCluster {
		forwarder, localPort, err := ec.coreClient.CoreV1.PortForward(ctx, pod, 2900)
		if err != nil {
			return err
		}
		defer forwarder.Close()

		endpoint = fmt.Sprintf("127.0.0.1:%d", localPort)
	}

	conn, err := net.Dial("tcp", endpoint)
	if err != nil {
		return xerrors.WithStack(err)
	}
	if _, err := io.Copy(conn, backupFile); err != nil {
		return xerrors.WithStack(err)
	}
	if err := conn.Close(); err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func (ec *EtcdController) setupCA(ctx context.Context, cluster *EtcdCluster) error {
	caSecret, err := cluster.CA()
	if err != nil {
		return err
	}
	if caSecret.CreationTimestamp.IsZero() {
		caSecret, err = ec.coreClient.CoreV1.CreateSecret(ctx, caSecret, metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
		cluster.SetCASecret(caSecret)
	}

	return nil
}

func (ec *EtcdController) setupServerCert(ctx context.Context, cluster *EtcdCluster) error {
	serverCertSecret, err := cluster.ServerCertSecret()
	if err != nil {
		return err
	}
	if serverCertSecret.CreationTimestamp.IsZero() {
		serverCertSecret, err = ec.coreClient.CoreV1.CreateSecret(ctx, serverCertSecret, metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
		cluster.SetServerCertSecret(serverCertSecret)
		return nil
	}

	if cluster.ShouldUpdateServerCertificate(serverCertSecret.Data[serverCertSecretCertName]) {
		serverCertSecret, err = cluster.ServerCertSecret()
		if err != nil {
			return err
		}

		serverCertSecret, err = ec.coreClient.CoreV1.UpdateSecret(ctx, serverCertSecret, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
		cluster.SetServerCertSecret(serverCertSecret)
	}

	return nil
}

func (ec *EtcdController) setupClientCert(ctx context.Context, cluster *EtcdCluster) error {
	clientCertSecret, err := cluster.ClientCertSecret()
	if err != nil {
		return err
	}
	if clientCertSecret.CreationTimestamp.IsZero() {
		clientCertSecret, err = ec.coreClient.CoreV1.CreateSecret(ctx, clientCertSecret, metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
		cluster.SetClientCertSecret(clientCertSecret)
		return nil
	}

	if cluster.ShouldUpdateClientCertificate(clientCertSecret.Data[clientCertSecretCertName]) {
		clientCertSecret, err = cluster.ClientCertSecret()
		if err != nil {
			return xerrors.WithStack(err)
		}

		clientCertSecret, err = ec.coreClient.CoreV1.UpdateSecret(ctx, clientCertSecret, metav1.UpdateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
		cluster.SetClientCertSecret(clientCertSecret)
	}

	return nil
}

func (ec *EtcdController) startMember(ctx context.Context, cluster *EtcdCluster, member *EtcdMember) error {
	ec.Log(ctx).Debug("Start member", zap.String("pod.name", member.Pod.Name))

	if member.PersistentVolumeClaim != nil && member.PersistentVolumeClaim.CreationTimestamp.IsZero() {
		_, err := ec.coreClient.CoreV1.CreatePersistentVolumeClaim(ctx, member.PersistentVolumeClaim, metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
	}

	if member.Pod.CreationTimestamp.IsZero() {
		cluster.SetAnnotationForPod(member.Pod)
		_, err := ec.coreClient.CoreV1.CreatePod(ctx, resetPod(member.Pod), metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
	}

	ec.EventRecorder().Event(cluster.EtcdCluster, corev1.EventTypeNormal, "MemberCreated", "The new member has been created")
	return nil
}

func (ec *EtcdController) deleteMember(ctx context.Context, cluster *EtcdCluster, member *EtcdMember) error {
	ec.Log(ctx).Debug("Delete the member", zap.String("pod.name", member.Pod.Name))

	eClient, forwarder, err := ec.etcdClient(ctx, cluster)
	if forwarder != nil {
		defer forwarder.Close()
	}
	if err != nil {
		return err
	}
	defer func() {
		if eClient != nil {
			eClient.Close()
		}
	}()
	err = eClient.WithTimeout(ctx, 3*time.Second, func(ctx context.Context) error {
		mList, err := eClient.MemberList(ctx)
		if err != nil {
			return xerrors.WithStack(err)
		}

		var memberStatus *etcdserverpb.Member
		for _, v := range mList.Members {
			ec.Log(ctx).Debug("Found the member", zap.String("name", v.Name), zap.Strings("peerURLs", v.PeerURLs))
			if len(v.PeerURLs) == 0 {
				ec.Log(ctx).Warn("The member hasn't any peer url", zap.Uint64("id", v.ID), zap.String("name", v.Name))
				continue
			}
			if strings.HasPrefix(v.PeerURLs[0], "https://"+strings.Replace(member.Pod.Status.PodIP, ".", "-", -1)) {
				memberStatus = v
			}
		}

		if memberStatus != nil {
			_, err = eClient.MemberRemove(ctx, memberStatus.ID)
			if err != nil {
				return xerrors.WithStack(err)
			}
			ec.Log(ctx).Debug("Remove the member from cluster", zap.String("name", memberStatus.Name), zap.Strings("peerURLs", memberStatus.PeerURLs))
		}

		if err := eClient.Close(); err != nil && !errors.Is(err, context.Canceled) {
			return xerrors.WithStack(err)
		}

		return nil
	})
	if err != nil {
		return xerrors.WithStack(err)
	}

	if forwarder != nil {
		forwarder.Close()
	}

	if err = ec.coreClient.CoreV1.DeletePod(ctx, member.Pod.Namespace, member.Pod.Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return xerrors.WithStack(err)
	}

	return nil
}

func (ec *EtcdController) updateMember(ctx context.Context, cluster *EtcdCluster, member *EtcdMember) error {
	ec.Log(ctx).Debug("Delete and start", zap.String("pod.name", member.Pod.Name))

	if !member.Pod.CreationTimestamp.IsZero() && cluster.ShouldUpdate(member.Pod) {
		if err := ec.deleteMember(ctx, cluster, member); err != nil {
			return err
		}
	}

	return nil
}

func (ec *EtcdController) ensureService(ctx context.Context, cluster *EtcdCluster) error {
	if err := ec.ensureDiscoveryService(ctx, cluster); err != nil {
		return err
	}
	if err := ec.ensureClientService(ctx, cluster); err != nil {
		return err
	}

	return nil
}

func (ec *EtcdController) setupDefragmentJob(ctx context.Context, cluster *EtcdCluster) error {
	found := true
	cj, err := ec.coreClient.BatchV1.GetCronJob(ctx, cluster.Namespace, cluster.DefragmentCronJobName(), metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		found = false
	} else if err != nil {
		return xerrors.WithStack(err)
	}

	if cluster.Spec.DefragmentSchedule == "" {
		if found {
			err = ec.coreClient.BatchV1.DeleteCronJob(ctx, cluster.Namespace, cluster.DefragmentCronJobName(), metav1.DeleteOptions{})
			if err != nil {
				return xerrors.WithStack(err)
			}
			return nil
		}

		return nil
	}

	if found {
		if !reflect.DeepEqual(cj.Spec, cluster.DefragmentCronJob().Spec) {
			_, err := ec.coreClient.BatchV1.UpdateCronJob(ctx, cluster.DefragmentCronJob(), metav1.UpdateOptions{})
			if err != nil {
				return xerrors.WithStack(err)
			}
		}
	} else {
		_, err := ec.coreClient.BatchV1.CreateCronJob(ctx, cluster.DefragmentCronJob(), metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
	}

	return nil
}

func (ec *EtcdController) ensureServiceAccount(ctx context.Context, cluster *EtcdCluster) error {
	sa, err := ec.serviceAccountLister.Get(cluster.Namespace, cluster.ServiceAccountName())
	if err != nil && apierrors.IsNotFound(err) {
		sa = cluster.ServiceAccount()

		sa, err = ec.coreClient.CoreV1.CreateServiceAccount(ctx, sa, metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
		_, err = ec.coreClient.RbacAuthorizationK8sIoV1.CreateRole(ctx, cluster.EtcdRole(), metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
		_, err = ec.coreClient.RbacAuthorizationK8sIoV1.CreateRoleBinding(ctx, cluster.EtcdRoleBinding(), metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
	} else if err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func (ec *EtcdController) ensureDiscoveryService(ctx context.Context, cluster *EtcdCluster) error {
	_, err := ec.serviceLister.Get(cluster.Namespace, cluster.ServerDiscoveryServiceName())
	if err != nil && apierrors.IsNotFound(err) {
		_, err = ec.coreClient.CoreV1.CreateService(ctx, cluster.DiscoveryService(), metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
	} else if err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func (ec *EtcdController) ensureClientService(ctx context.Context, cluster *EtcdCluster) error {
	_, err := ec.serviceLister.Get(cluster.Namespace, cluster.ClientServiceName())
	if err != nil && apierrors.IsNotFound(err) {
		_, err = ec.coreClient.CoreV1.CreateService(ctx, cluster.ClientService(), metav1.CreateOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}
	} else if err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func (ec *EtcdController) checkClusterStatus(ctx context.Context, cluster *EtcdCluster) error {
	cluster.Status.Members = make([]etcdv1alpha2.MemberStatus, 0)

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

			pf, port, err := ec.coreClient.CoreV1.PortForward(ctx, v, EtcdClientPort)
			if err != nil {
				ec.Log(ctx).Info("Failed port forward", zap.Error(err))
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
			ec.Log(ctx).Debug("Close all port forwarders")
			for _, v := range forwarder {
				v.Close()
			}
		}()
	}

	endpoints := make([]string, 0)
	runningPods := 0
	for _, v := range etcdPods {
		if v.Status.Phase == corev1.PodPhaseRunning {
			runningPods++
		}
		endpoints = append(endpoints, v.Endpoint)
	}

	etcdClient, err := cluster.Client(endpoints)
	if err != nil {
		cluster.Status.Ready = false
		return nil
	}
	defer func() {
		if err := etcdClient.Close(); err != nil && !errors.Is(err, context.Canceled) {
			ec.Log(ctx).Info("Failed close etcd client", zap.Error(err))
		}
	}()

	mlCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	memberList, err := etcdClient.MemberList(mlCtx)
	if err != nil {
		cancel()
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
			ec.Log(ctx).Info("Failed get status", zap.Error(err))
			continue
		}
		etcdPods[i].StatusResponse = st
	}
	cancel()

	for _, m := range memberList.Members {
		ms := etcdv1alpha2.MemberStatus{
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
			ms.PodName = p.Name
			ms.Learner = p.IsLearner
			ms.DBSize = p.StatusResponse.DbSize
			ms.InUseSize = p.StatusResponse.DbSizeInUse
		}

		cluster.Status.Members = append(cluster.Status.Members, ms)
	}

	sort.Slice(cluster.Status.Members, func(i, j int) bool {
		return cluster.Status.Members[i].Name < cluster.Status.Members[j].Name
	})

	if cluster.Spec.Members == 1 && len(cluster.Status.Members) == 1 && cluster.Status.Members[0].Leader {
		if !cluster.Status.Ready {
			now := metav1.Now()
			cluster.Status.LastReadyTransitionTime = &now
		}
		cluster.Status.Ready = true
		cluster.Status.CreatingCompleted = true
		return nil
	}

	if cluster.Spec.Members > 1 && len(cluster.Status.Members) > cluster.Spec.Members/2 {
		if !cluster.Status.Ready {
			now := metav1.Now()
			cluster.Status.LastReadyTransitionTime = &now
		}
	}

	if len(cluster.Status.Members) == cluster.Spec.Members &&
		runningPods == cluster.Spec.Members && !cluster.Status.CreatingCompleted {
		cluster.Status.CreatingCompleted = true
	}

	return nil
}

func (ec *EtcdController) updateStatus(ctx context.Context, cluster *EtcdCluster) {
	cluster.Status.Phase = cluster.CurrentPhase()
	switch cluster.Status.Phase {
	case etcdv1alpha2.EtcdClusterPhaseRunning, etcdv1alpha2.EtcdClusterPhaseUpdating, etcdv1alpha2.EtcdClusterPhaseDegrading:
		if cluster.Status.Ready && cluster.Status.Restored != nil && !cluster.Status.Restored.Completed {
			cluster.Status.Restored.Completed = true
			if cluster.Status.Restored.RestoredTime == nil {
				now := metav1.Now()
				cluster.Status.Restored.RestoredTime = &now
			}
		}
	}
	ec.Log(ctx).Debug("Current Phase",
		zap.String("phase", string(cluster.Status.Phase)),
		zap.String("cluster.name", cluster.Name),
	)

	if cluster.Spec.Members == 1 {
		if len(cluster.Status.Members) == 1 && cluster.Status.Members[0].Leader {
			cluster.Status.Ready = true
		} else {
			cluster.Status.Ready = false
		}
	}
	if cluster.Spec.Members > 1 {
		if len(cluster.Status.Members) > cluster.Spec.Members/2 {
			cluster.Status.Ready = true
		} else {
			cluster.Status.Ready = false
		}
	}

	cluster.Status.ClientCertSecretName = cluster.ClientCertSecretName()
	cluster.Status.ClientEndpoint = fmt.Sprintf("https://%s.%s.svc.%s:%d", cluster.ClientServiceName(), cluster.Namespace, cluster.ClusterDomain, EtcdClientPort)

	s := labels.SelectorFromSet(map[string]string{
		etcd.LabelNameClusterName: cluster.Name,
		etcd.LabelNameRole:        "defragment",
	})
	jobList, err := ec.coreClient.BatchV1.ListJob(ctx, cluster.Namespace, metav1.ListOptions{LabelSelector: s.String()})
	if err != nil {
		return
	}

	for _, v := range jobList.Items {
		if v.Status.Succeeded != 1 {
			continue
		}

		if cluster.Status.LastDefragmentTime.Before(v.Status.CompletionTime.Time) {
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
		logger.Log.Debug("Never backed up")
		return true
	}
	if cluster.Status.Backup.LastSucceededTime.IsZero() {
		logger.Log.Debug("LastSucceededTime is zero")
		return true
	}
	if cluster.Status.Backup.LastSucceededTime.Time.Add(time.Duration(cluster.Spec.Backup.IntervalInSeconds) * time.Second).Before(time.Now()) {
		logger.Log.Debug("Backed up is expired")
		return true
	}

	return false
}

func (ec *EtcdController) doBackup(ctx context.Context, cluster *EtcdCluster) error {
	now := metav1.Now()
	backupStatus := &etcdv1alpha2.BackupStatusHistory{ExecuteTime: &now}
	defer func() {
		if cluster.Status.Backup == nil {
			cluster.Status.Backup = &etcdv1alpha2.BackupStatus{}
		}
		cluster.Status.Backup.History = append([]etcdv1alpha2.BackupStatusHistory{*backupStatus}, cluster.Status.Backup.History...)
	}()

	client, forwarder, err := ec.etcdClient(ctx, cluster)
	if forwarder != nil {
		defer forwarder.Close()
	}
	if err != nil {
		return err
	}
	defer func() {
		if client != nil {
			client.Close()
		}
	}()

	tmpFile, err := os.CreateTemp("", "")
	if err != nil {
		return xerrors.WithStack(err)
	}
	defer os.Remove(tmpFile.Name())

	data, err := client.Snapshot(ctx)
	if err != nil {
		return xerrors.WithStack(err)
	}
	dataSize, err := io.Copy(tmpFile, data)
	if err != nil {
		return xerrors.WithStack(err)
	}
	if err := tmpFile.Sync(); err != nil {
		return xerrors.WithStack(err)
	}
	if err := data.Close(); err != nil {
		return xerrors.WithStack(err)
	}

	sm := snapshot.NewV3(logger.Log)
	dbStatus, err := sm.Status(tmpFile.Name())
	if err != nil {
		return xerrors.WithStack(err)
	}
	backupStatus.EtcdRevision = dbStatus.Revision

	f, err := os.Open(tmpFile.Name())
	if err != nil {
		return xerrors.WithStack(err)
	}
	if err := ec.storeBackupFile(ctx, cluster, backupStatus, f, dataSize, now); err != nil {
		return err
	}

	backupStatus.Succeeded = true
	return nil
}

func (ec *EtcdController) storeBackupFile(ctx context.Context, cluster *EtcdCluster, backupStatus *etcdv1alpha2.BackupStatusHistory, data io.Reader, dataSize int64, t metav1.Time) error {
	switch {
	case cluster.Spec.Backup.Storage.MinIO != nil:
		spec := cluster.Spec.Backup.Storage.MinIO

		mc, forwarder, err := ec.minioClient(ctx, spec)
		if forwarder != nil {
			defer forwarder.Close()
		}
		if err != nil {
			return err
		}
		filename := fmt.Sprintf("%s_%d", cluster.Name, t.Unix())
		path := spec.Path
		if path[0] == '/' {
			path = path[1:]
		}
		backupStatus.Path = filepath.Join(path, filename)
		_, err = mc.PutObject(ctx, spec.Bucket, filepath.Join(path, filename), data, dataSize, minio.PutObjectOptions{})
		if err != nil {
			return xerrors.WithStack(err)
		}

		return nil
	case cluster.Spec.Backup.Storage.GCS != nil:
		spec := cluster.Spec.Backup.Storage.GCS
		namespace := spec.CredentialSelector.Namespace
		if namespace == "" {
			namespace = cluster.Namespace
		}
		credential, err := ec.secretLister.Get(namespace, spec.CredentialSelector.Name)
		if err != nil {
			return xerrors.WithStack(err)
		}
		b, ok := credential.Data[spec.CredentialSelector.ServiceAccountJSONKey]
		if !ok {
			return xerrors.NewfWithStack("%s is not found", spec.CredentialSelector.ServiceAccountJSONKey)
		}

		client, err := storage.NewClient(ctx, option.WithCredentialsJSON(b))
		if err != nil {
			return xerrors.WithStack(err)
		}

		filename := fmt.Sprintf("%s_%d", cluster.Name, t.Unix())
		obj := client.Bucket(spec.Bucket).Object(filepath.Join(spec.Path, filename))
		w := obj.NewWriter(ctx)
		if _, err := io.Copy(w, data); err != nil {
			return xerrors.WithStack(err)
		}
		if err := w.Close(); err != nil {
			return xerrors.WithStack(err)
		}
		backupStatus.Path = filepath.Join(spec.Path, filename)

		return nil
	default:
		return xerrors.NewWithStack("Not configured a storage")
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

		mc, forwarder, err := ec.minioClient(ctx, spec)
		if forwarder != nil {
			defer forwarder.Close()
		}
		if err != nil {
			return err
		}
		listCh := mc.ListObjects(ctx, spec.Bucket, minio.ListObjectsOptions{Prefix: spec.Path + "/", Recursive: false})
		backupFiles := make([]string, 0)
		for obj := range listCh {
			if obj.Err != nil {
				return xerrors.WithStack(err)
			}
			if strings.HasPrefix(obj.Key, filepath.Join(spec.Path, cluster.Name)) {
				backupFiles = append(backupFiles, obj.Key)
			}
		}
		ec.Log(ctx).Debug("Backup files", zap.Strings("files", backupFiles))
		if len(backupFiles) <= cluster.Spec.Backup.MaxBackups {
			return nil
		}
		sort.Strings(backupFiles)
		sort.Sort(sort.Reverse(sort.StringSlice(backupFiles)))
		purgeTargets := backupFiles[cluster.Spec.Backup.MaxBackups:]
		for _, v := range purgeTargets {
			if err := mc.RemoveObject(ctx, spec.Bucket, v, minio.RemoveObjectOptions{}); err != nil {
				return xerrors.WithStack(err)
			}
		}

		return nil
	case cluster.Spec.Backup.Storage.GCS != nil:
		spec := cluster.Spec.Backup.Storage.GCS
		namespace := spec.CredentialSelector.Namespace
		if namespace == "" {
			namespace = cluster.Namespace
		}
		credential, err := ec.secretLister.Get(namespace, spec.CredentialSelector.Name)
		if err != nil {
			return xerrors.WithStack(err)
		}
		b, ok := credential.Data[spec.CredentialSelector.ServiceAccountJSONKey]
		if !ok {
			return xerrors.NewfWithStack("%s is not found", spec.CredentialSelector.ServiceAccountJSONKey)
		}
		client, err := storage.NewClient(ctx, option.WithCredentialsJSON(b))
		if err != nil {
			return xerrors.WithStack(err)
		}
		bh := client.Bucket(spec.Bucket)

		backupFiles := make([]string, 0)
		iter := bh.Objects(ctx, &storage.Query{Prefix: spec.Path})
		for {
			attr, err := iter.Next()
			if errors.Is(err, iterator.Done) {
				break
			}
			if err != nil {
				return xerrors.WithStack(err)
			}
			backupFiles = append(backupFiles, attr.Name)
		}
		ec.Log(ctx).Debug("Backup files", zap.Strings("files", backupFiles))
		if len(backupFiles) <= cluster.Spec.Backup.MaxBackups {
			return nil
		}
		sort.Strings(backupFiles)
		sort.Sort(sort.Reverse(sort.StringSlice(backupFiles)))
		purgeTargets := backupFiles[cluster.Spec.Backup.MaxBackups:]
		for _, v := range purgeTargets {
			ec.Log(ctx).Debug("Delete backup file", zap.String("target", v))
			if err := bh.Object(v).Delete(ctx); err != nil {
				return xerrors.WithStack(err)
			}
		}

		return nil
	default:
		return xerrors.NewWithStack("Not configured a storage")
	}
}

func (ec *EtcdController) getBackupFile(ctx context.Context, cluster *EtcdCluster, path string) (io.ReadCloser, *portforward.PortForwarder, error) {
	switch {
	case cluster.Spec.Backup.Storage.MinIO != nil:
		spec := cluster.Spec.Backup.Storage.MinIO

		mc, forwarder, err := ec.minioClient(ctx, spec)
		if err != nil {
			return nil, forwarder, err
		}

		obj, err := mc.GetObject(ctx, spec.Bucket, path, minio.GetObjectOptions{})
		if err != nil {
			return nil, forwarder, xerrors.WithStack(err)
		}
		if stat, err := obj.Stat(); err != nil {
			return nil, forwarder, xerrors.WithStack(err)
		} else {
			if stat.Size == 0 {
				return nil, forwarder, xerrors.NewWithStack("backup file is empty")
			}
		}

		return obj, forwarder, nil
	default:
		return nil, nil, errors.New("not supported")
	}
}

func (ec *EtcdController) minioClient(ctx context.Context, spec *etcdv1alpha2.BackupStorageMinIOSpec) (*minio.Client, *portforward.PortForwarder, error) {
	svc, err := ec.serviceLister.Get(spec.ServiceSelector.Namespace, spec.ServiceSelector.Name)
	if err != nil {
		return nil, nil, xerrors.WithStack(err)
	}

	instanceEndpoint := fmt.Sprintf("%s.%s.svc:%d", svc.Name, svc.Namespace, svc.Spec.Ports[0].Port)
	var forwarder *portforward.PortForwarder
	if ec.runOutsideCluster {
		selector := labels.SelectorFromSet(svc.Spec.Selector)
		pods, err := ec.podLister.List(svc.Namespace, selector)
		if err != nil {
			return nil, nil, xerrors.WithStack(err)
		}
		var targetPod *corev1.Pod
		for _, v := range pods {
			if v.Status.Phase == corev1.PodPhaseRunning {
				targetPod = v
				break
			}
		}
		if targetPod == nil {
			return nil, nil, xerrors.New("all pods are not running")
		}

		f, port, err := ec.coreClient.CoreV1.PortForward(ctx, targetPod, svc.Spec.Ports[0].Port)
		if err != nil {
			return nil, nil, err
		}
		forwarder = f

		instanceEndpoint = fmt.Sprintf("127.0.0.1:%d", port)
	}

	credential, err := ec.secretLister.Get(spec.CredentialSelector.Namespace, spec.CredentialSelector.Name)
	if err != nil {
		return nil, forwarder, xerrors.WithStack(err)
	}

	creds := credentials.NewStaticV4(string(credential.Data[spec.CredentialSelector.AccessKeyIDKey]), string(credential.Data[spec.CredentialSelector.SecretAccessKeyKey]), "")
	mc, err := minio.New(instanceEndpoint, &minio.Options{Creds: creds, Secure: spec.Secure, Transport: ec.transport})
	if err != nil {
		return nil, forwarder, xerrors.WithStack(err)
	}

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

func (ec *EtcdController) etcdClient(ctx context.Context, cluster *EtcdCluster) (*etcdv3Client, *portforward.PortForwarder, error) {
	var endpoints []string
	var forwarder *portforward.PortForwarder
	if ec.runOutsideCluster {
		pods := cluster.AllMembers()
		for _, v := range pods {
			if cluster.IsPodReady(v.Pod) {
				f, port, err := ec.coreClient.CoreV1.PortForward(ctx, v.Pod, EtcdClientPort)
				if err != nil {
					return nil, nil, err
				}
				forwarder = f

				endpoints = []string{fmt.Sprintf("https://127.0.0.1:%d", port)}
				ec.Log(ctx).Debug("Port forward", zap.String("to", v.Pod.Name))
				break
			}
		}
	}

	client, err := cluster.Client(endpoints)
	if err != nil {
		return nil, forwarder, err
	}

	return &etcdv3Client{Client: client}, forwarder, nil
}
