package etcd

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	etcdv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha2"
	"go.f110.dev/heimdallr/operator/pkg/client/versioned/scheme"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
)

func Factory(base *etcdv1alpha2.EtcdCluster, traits ...k8sfactory.Trait) *etcdv1alpha2.EtcdCluster {
	var e *etcdv1alpha2.EtcdCluster
	if base == nil {
		e = &etcdv1alpha2.EtcdCluster{}
	} else {
		e = base
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
	e.Status.Phase = etcdv1alpha2.ClusterPhaseRunning
	e.Status.ClientCertSecretName = fmt.Sprintf("%s-client-cert", e.Name)
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

func BackupToMinIO(bucket, path string, secure bool, svcName, svcNamespace string, creds etcdv1alpha2.AWSCredentialSelector) k8sfactory.Trait {
	return func(object interface{}) {
		e, ok := object.(*etcdv1alpha2.EtcdCluster)
		if !ok {
			return
		}

		e.Spec.Backup.Storage.MinIO = &etcdv1alpha2.BackupStorageMinIOSpec{
			Bucket: bucket,
			Path:   path,
			Secure: secure,
			ServiceSelector: etcdv1alpha2.ObjectSelector{
				Name:      svcName,
				Namespace: svcNamespace,
			},
			CredentialSelector: creds,
		}
	}
}

func BackupToGCS(bucket, path string, creds etcdv1alpha2.GCPCredentialSelector) k8sfactory.Trait {
	return func(object interface{}) {
		e, ok := object.(*etcdv1alpha2.EtcdCluster)
		if !ok {
			return
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
