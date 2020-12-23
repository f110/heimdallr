package etcd

import (
	"reflect"

	"go.uber.org/zap"
	"golang.org/x/xerrors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	etcdv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha1"
	etcdv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha2"
	"go.f110.dev/heimdallr/operator/pkg/webhook"
	"go.f110.dev/heimdallr/pkg/logger"
)

func register(kind string, f webhook.ConvertFunc, b webhook.ConvertFunc) {
	fromGV := etcdv1alpha1.SchemeGroupVersion
	to := etcdv1alpha2.SchemeGroupVersion

	from := fromGV.WithKind(kind)
	webhook.DefaultConverter.Register(&from, &to, f)

	fromGV = etcdv1alpha2.SchemeGroupVersion
	from = fromGV.WithKind(kind)
	to = etcdv1alpha1.SchemeGroupVersion
	webhook.DefaultConverter.Register(&from, &to, b)
}

func init() {
	register("EtcdCluster", V1Alpha1EtcdClusterToV1Alpha2EtcdCluster, V1Alpha2EtcdClusterToV1Alpha1EtcdCluster)
}

func V1Alpha1EtcdClusterToV1Alpha2EtcdCluster(in runtime.Object) (runtime.Object, error) {
	// in is UnstructuredJSONScheme
	un, ok := in.(runtime.Unstructured)
	if !ok {
		logger.Log.Error("in is not Unstructured", zap.String("type_of", reflect.TypeOf(in).String()))
		return nil, xerrors.New("unexpected input data type")
	}

	before := &etcdv1alpha1.EtcdCluster{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.UnstructuredContent(), before)
	if err != nil {
		logger.Log.Warn("Failed convert to the object from unstructured", zap.Error(err))
		return nil, err
	}

	after := &etcdv1alpha2.EtcdCluster{
		TypeMeta: metav1.TypeMeta{
			APIVersion: etcdv1alpha2.SchemeGroupVersion.String(),
			Kind:       before.Kind,
		},
		ObjectMeta: before.ObjectMeta,
		Spec: etcdv1alpha2.EtcdClusterSpec{
			Members:             before.Spec.Members,
			Version:             before.Spec.Version,
			AntiAffinity:        before.Spec.AntiAffinity,
			DefragmentSchedule:  before.Spec.DefragmentSchedule,
			VolumeClaimTemplate: before.Spec.VolumeClaimTemplate,
		},
		Status: etcdv1alpha2.EtcdClusterStatus{
			Ready:                   before.Status.Ready,
			Phase:                   etcdv1alpha2.EtcdClusterPhase(before.Status.Phase),
			LastReadyTransitionTime: before.Status.LastReadyTransitionTime,
			LastDefragmentTime:      before.Status.LastDefragmentTime,
			ClientEndpoint:          before.Status.ClientEndpoint,
			ClientCertSecretName:    before.Status.ClientCertSecretName,
			Backup: &etcdv1alpha2.BackupStatus{
				Succeeded:         before.Status.Backup.Succeeded,
				LastSucceededTime: before.Status.Backup.LastSucceededTime,
			},
			Restored: &etcdv1alpha2.RestoredStatus{
				Completed:    before.Status.Restored.Completed,
				Path:         before.Status.Restored.Path,
				BackupTime:   before.Status.Restored.BackupTime,
				RestoredTime: before.Status.Restored.RestoredTime,
			},
		},
	}

	if before.Spec.Backup != nil {
		after.Spec.Backup = &etcdv1alpha2.BackupSpec{
			IntervalInSecond: before.Spec.Backup.IntervalInSecond,
			MaxBackups:       before.Spec.Backup.MaxBackups,
			Storage:          etcdv1alpha2.BackupStorageSpec{},
		}

		if before.Spec.Backup.Storage.MinIO != nil {
			after.Spec.Backup.Storage.MinIO = &etcdv1alpha2.BackupStorageMinIOSpec{
				ServiceSelector: etcdv1alpha2.ObjectSelector{
					Name:      before.Spec.Backup.Storage.MinIO.ServiceSelector.Name,
					Namespace: before.Spec.Backup.Storage.MinIO.ServiceSelector.Namespace,
				},
				CredentialSelector: etcdv1alpha2.AWSCredentialSelector{
					Name:               before.Spec.Backup.Storage.MinIO.CredentialSelector.Name,
					Namespace:          before.Spec.Backup.Storage.MinIO.CredentialSelector.Namespace,
					AccessKeyIDKey:     before.Spec.Backup.Storage.MinIO.CredentialSelector.AccessKeyIDKey,
					SecretAccessKeyKey: before.Spec.Backup.Storage.MinIO.CredentialSelector.SecretAccessKeyKey,
				},
				Bucket: before.Spec.Backup.Storage.MinIO.Bucket,
				Path:   before.Spec.Backup.Storage.MinIO.Path,
				Secure: before.Spec.Backup.Storage.MinIO.Secure,
			}
		}

		if before.Spec.Backup.Storage.GCS != nil {
			after.Spec.Backup.Storage.GCS = &etcdv1alpha2.BackupStorageGCSSpec{
				Bucket: before.Spec.Backup.Storage.GCS.Bucket,
				Path:   before.Spec.Backup.Storage.GCS.Path,
				CredentialSelector: etcdv1alpha2.GCPCredentialSelector{
					Name:                  before.Spec.Backup.Storage.GCS.CredentialSelector.Name,
					Namespace:             before.Spec.Backup.Storage.GCS.CredentialSelector.Namespace,
					ServiceAccountJSONKey: before.Spec.Backup.Storage.GCS.CredentialSelector.ServiceAccountJSONKey,
				},
			}
		}
	}

	if before.Status.Backup != nil {
		backupHistory := make([]etcdv1alpha2.BackupStatusHistory, 0)
		for _, v := range before.Status.Backup.History {
			backupHistory = append(backupHistory, etcdv1alpha2.BackupStatusHistory{
				Succeeded:    v.Succeeded,
				ExecuteTime:  v.ExecuteTime,
				Path:         v.Path,
				EtcdVersion:  v.EtcdVersion,
				EtcdRevision: v.EtcdRevision,
				Message:      v.Message,
			})
		}
		after.Status.Backup.History = backupHistory
	}

	members := make([]etcdv1alpha2.MemberStatus, 0)
	for _, v := range before.Status.Members {
		members = append(members, etcdv1alpha2.MemberStatus{
			Id:      v.Id,
			Name:    v.Name,
			PodName: v.PodName,
			Leader:  v.Leader,
			Learner: v.Learner,
			Version: v.Version,
		})
	}
	after.Status.Members = members

	return after, nil
}

func V1Alpha2EtcdClusterToV1Alpha1EtcdCluster(in runtime.Object) (runtime.Object, error) {
	// in is UnstructuredJSONScheme
	un, ok := in.(runtime.Unstructured)
	if !ok {
		logger.Log.Error("in is not Unstructured", zap.String("type_of", reflect.TypeOf(in).String()))
		return nil, xerrors.New("unexpected input data type")
	}

	before := &etcdv1alpha2.EtcdCluster{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.UnstructuredContent(), before)
	if err != nil {
		logger.Log.Warn("Failed convert to the object from unstructured", zap.Error(err))
		return nil, err
	}

	after := &etcdv1alpha1.EtcdCluster{
		TypeMeta: metav1.TypeMeta{
			APIVersion: etcdv1alpha1.SchemeGroupVersion.String(),
			Kind:       before.Kind,
		},
		ObjectMeta: before.ObjectMeta,
		Spec:       etcdv1alpha1.EtcdClusterSpec{},
		Status: etcdv1alpha1.EtcdClusterStatus{
			Ready:                   before.Status.Ready,
			Phase:                   etcdv1alpha1.EtcdClusterPhase(before.Status.Phase),
			LastReadyTransitionTime: before.Status.LastReadyTransitionTime,
			LastDefragmentTime:      before.Status.LastDefragmentTime,
			ClientEndpoint:          before.Status.ClientEndpoint,
			ClientCertSecretName:    before.Status.ClientCertSecretName,
			Backup:                  &etcdv1alpha1.BackupStatus{},
			Restored:                &etcdv1alpha1.RestoredStatus{},
		},
	}

	if before.Spec.Backup != nil {
		after.Spec.Backup = &etcdv1alpha1.BackupSpec{
			IntervalInSecond: before.Spec.Backup.IntervalInSecond,
			MaxBackups:       before.Spec.Backup.MaxBackups,
			Storage:          etcdv1alpha1.BackupStorageSpec{},
		}

		if before.Spec.Backup.Storage.MinIO != nil {
			after.Spec.Backup.Storage.MinIO = &etcdv1alpha1.BackupStorageMinIOSpec{
				ServiceSelector: etcdv1alpha1.ObjectSelector{
					Name:      before.Spec.Backup.Storage.MinIO.ServiceSelector.Name,
					Namespace: before.Spec.Backup.Storage.MinIO.ServiceSelector.Namespace,
				},
				CredentialSelector: etcdv1alpha1.AWSCredentialSelector{
					Name:               before.Spec.Backup.Storage.MinIO.CredentialSelector.Name,
					Namespace:          before.Spec.Backup.Storage.MinIO.CredentialSelector.Namespace,
					AccessKeyIDKey:     before.Spec.Backup.Storage.MinIO.CredentialSelector.AccessKeyIDKey,
					SecretAccessKeyKey: before.Spec.Backup.Storage.MinIO.CredentialSelector.SecretAccessKeyKey,
				},
				Bucket: before.Spec.Backup.Storage.MinIO.Bucket,
				Path:   before.Spec.Backup.Storage.MinIO.Path,
				Secure: before.Spec.Backup.Storage.MinIO.Secure,
			}
		}

		if before.Spec.Backup.Storage.GCS != nil {
			after.Spec.Backup.Storage.GCS = &etcdv1alpha1.BackupStorageGCSSpec{
				Bucket: before.Spec.Backup.Storage.GCS.Bucket,
				Path:   before.Spec.Backup.Storage.GCS.Path,
				CredentialSelector: etcdv1alpha1.GCPCredentialSelector{
					Name:                  before.Spec.Backup.Storage.GCS.CredentialSelector.Name,
					Namespace:             before.Spec.Backup.Storage.GCS.CredentialSelector.Namespace,
					ServiceAccountJSONKey: before.Spec.Backup.Storage.GCS.CredentialSelector.ServiceAccountJSONKey,
				},
			}
		}
	}

	if before.Status.Backup != nil {
		backupHistory := make([]etcdv1alpha1.BackupStatusHistory, 0)
		for _, v := range before.Status.Backup.History {
			backupHistory = append(backupHistory, etcdv1alpha1.BackupStatusHistory{
				Succeeded:    v.Succeeded,
				ExecuteTime:  v.ExecuteTime,
				Path:         v.Path,
				EtcdVersion:  v.EtcdVersion,
				EtcdRevision: v.EtcdRevision,
				Message:      v.Message,
			})
		}
		after.Status.Backup.History = backupHistory
	}

	members := make([]etcdv1alpha1.MemberStatus, 0)
	for _, v := range before.Status.Members {
		members = append(members, etcdv1alpha1.MemberStatus{
			Id:      v.Id,
			Name:    v.Name,
			PodName: v.PodName,
			Leader:  v.Leader,
			Learner: v.Learner,
			Version: v.Version,
		})
	}
	after.Status.Members = members

	return after, nil
}
