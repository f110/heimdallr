package etcd

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	etcdv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha2"
	"go.f110.dev/heimdallr/operator/pkg/client/versioned/scheme"
)

type Trait func(e *etcdv1alpha2.EtcdCluster)

func Factory(base *etcdv1alpha2.EtcdCluster, traits ...Trait) *etcdv1alpha2.EtcdCluster {
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

func Name(v string) Trait {
	return func(e *etcdv1alpha2.EtcdCluster) {
		e.SetName(v)
	}
}

func Namespace(v string) Trait {
	return func(e *etcdv1alpha2.EtcdCluster) {
		e.SetNamespace(v)
	}
}

func Ready(e *etcdv1alpha2.EtcdCluster) {
	e.Status.Ready = true
	now := metav1.Now()
	e.Status.LastReadyTransitionTime = &now
}

func CreatingCompleted(e *etcdv1alpha2.EtcdCluster) {
	e.Status.CreatingCompleted = true
}

func Version(v string) Trait {
	return func(e *etcdv1alpha2.EtcdCluster) {
		e.Spec.Version = v
	}
}

func HighAvailability(e *etcdv1alpha2.EtcdCluster) {
	e.Spec.Members = 3
	e.Spec.AntiAffinity = true
}

func DisableAntiAffinity(e *etcdv1alpha2.EtcdCluster) {
	e.Spec.AntiAffinity = false
}

func BackupByMinIO(bucket, path string, svc *corev1.Service) Trait {
	return func(e *etcdv1alpha2.EtcdCluster) {
		e.Spec.Backup = &etcdv1alpha2.BackupSpec{
			IntervalInSecond: 60,
			MaxBackups:       5,
			Storage: etcdv1alpha2.BackupStorageSpec{
				MinIO: &etcdv1alpha2.BackupStorageMinIOSpec{
					Bucket: bucket,
					Path:   path,
					ServiceSelector: etcdv1alpha2.ObjectSelector{
						Name:      svc.Name,
						Namespace: svc.Namespace,
					},
					CredentialSelector: etcdv1alpha2.AWSCredentialSelector{
						Name:               "minio-token",
						Namespace:          metav1.NamespaceDefault,
						AccessKeyIDKey:     "accesskey",
						SecretAccessKeyKey: "secretkey",
					},
				},
			},
		}
	}
}

func PersistentData(e *etcdv1alpha2.EtcdCluster) {
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
