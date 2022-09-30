package etcd

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.f110.dev/heimdallr/pkg/k8s/api/etcdv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/client/versioned/scheme"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
)

func Factory(base *etcdv1alpha2.EtcdCluster, traits ...k8sfactory.Trait) *etcdv1alpha2.EtcdCluster {
	var e *etcdv1alpha2.EtcdCluster
	if base == nil {
		e = &etcdv1alpha2.EtcdCluster{}
	} else {
		e = base.DeepCopy()
	}
	if e.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(e)
		if err == nil && !unversioned && len(gvks) > 0 {
			e.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, trait := range traits {
		trait(e)
	}

	return e
}

func Ready(object interface{}) {
	e, ok := object.(*etcdv1alpha2.EtcdCluster)
	if !ok {
		return
	}

	e.Status.Ready = true
	now := metav1.Now()
	e.Status.LastReadyTransitionTime = &now
	e.Status.Phase = etcdv1alpha2.EtcdClusterPhaseRunning
	e.Status.ClientCertSecretName = fmt.Sprintf("%s-client-cert", e.Name)
	e.Status.CreatingCompleted = true
}

func CreatingCompleted(object interface{}) {
	e, ok := object.(*etcdv1alpha2.EtcdCluster)
	if !ok {
		return
	}

	e.Status.CreatingCompleted = true
}

func Member(v int) k8sfactory.Trait {
	return func(object interface{}) {
		e, ok := object.(*etcdv1alpha2.EtcdCluster)
		if !ok {
			return
		}
		e.Spec.Members = v
	}
}

func Version(v string) k8sfactory.Trait {
	return func(object interface{}) {
		e, ok := object.(*etcdv1alpha2.EtcdCluster)
		if !ok {
			return
		}

		e.Spec.Version = v
	}
}

func DefragmentSchedule(v string) k8sfactory.Trait {
	return func(object interface{}) {
		e, ok := object.(*etcdv1alpha2.EtcdCluster)
		if !ok {
			return
		}

		e.Spec.DefragmentSchedule = v
	}
}

func HighAvailability(object interface{}) {
	e, ok := object.(*etcdv1alpha2.EtcdCluster)
	if !ok {
		return
	}
	e.Spec.Members = 3
	e.Spec.AntiAffinity = true
}

func EnableAntiAffinity(object interface{}) {
	e, ok := object.(*etcdv1alpha2.EtcdCluster)
	if !ok {
		return
	}
	e.Spec.AntiAffinity = true
}

func DisableAntiAffinity(object interface{}) {
	e, ok := object.(*etcdv1alpha2.EtcdCluster)
	if !ok {
		return
	}
	e.Spec.AntiAffinity = false
}

func Phase(p etcdv1alpha2.EtcdClusterPhase) k8sfactory.Trait {
	return func(object interface{}) {
		e, ok := object.(*etcdv1alpha2.EtcdCluster)
		if !ok {
			return
		}
		e.Status.Phase = p
	}
}

func CreatedStatus(object interface{}) {
	e, ok := object.(*etcdv1alpha2.EtcdCluster)
	if !ok {
		return
	}
	e.Status.ClientEndpoint = fmt.Sprintf("https://%s-client.%s.svc.cluster.local:2379", e.Name, e.Namespace)
	e.Status.ClientCertSecretName = fmt.Sprintf("etcd-%s-client-cert", e.Name)
}

func Backup(interval, maxBackups int) k8sfactory.Trait {
	return func(object interface{}) {
		e, ok := object.(*etcdv1alpha2.EtcdCluster)
		if !ok {
			return
		}
		e.Spec.Backup = &etcdv1alpha2.BackupSpec{
			IntervalInSecond: interval,
			MaxBackups:       maxBackups,
		}
	}
}

func BackupToMinIO(bucket, path string, secure bool, svcName, svcNamespace string, creds *etcdv1alpha2.AWSCredentialSelector) k8sfactory.Trait {
	return func(object interface{}) {
		e, ok := object.(*etcdv1alpha2.EtcdCluster)
		if !ok {
			return
		}

		if e.Spec.Backup.Storage == nil {
			e.Spec.Backup.Storage = &etcdv1alpha2.BackupStorageSpec{}
		}
		e.Spec.Backup.Storage.MinIO = &etcdv1alpha2.BackupStorageMinIOSpec{
			Bucket: bucket,
			Path:   path,
			Secure: secure,
			ServiceSelector: &etcdv1alpha2.ObjectSelector{
				Name:      svcName,
				Namespace: svcNamespace,
			},
			CredentialSelector: creds,
		}
	}
}

func BackupToGCS(bucket, path string, creds *etcdv1alpha2.GCPCredentialSelector) k8sfactory.Trait {
	return func(object interface{}) {
		e, ok := object.(*etcdv1alpha2.EtcdCluster)
		if !ok {
			return
		}

		if e.Spec.Backup.Storage == nil {
			e.Spec.Backup.Storage = &etcdv1alpha2.BackupStorageSpec{}
		}
		e.Spec.Backup.Storage.GCS = &etcdv1alpha2.BackupStorageGCSSpec{
			Bucket:             bucket,
			Path:               path,
			CredentialSelector: creds,
		}
	}
}

func PersistentData(object interface{}) {
	e, ok := object.(*etcdv1alpha2.EtcdCluster)
	if !ok {
		return
	}

	e.Spec.VolumeClaimTemplate = &corev1.PersistentVolumeClaimTemplate{
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					"storage": resource.MustParse("1Gi"),
				},
			},
		},
	}
}

func MemberStatus(statuses []etcdv1alpha2.MemberStatus) k8sfactory.Trait {
	return func(object interface{}) {
		e, ok := object.(*etcdv1alpha2.EtcdCluster)
		if !ok {
			return
		}

		if statuses == nil {
			e.Status.Members = make([]etcdv1alpha2.MemberStatus, 0)
		} else {
			e.Status.Members = statuses
		}
	}
}
