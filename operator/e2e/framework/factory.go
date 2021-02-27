package framework

import (
	certmanagermetav1 "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	etcdv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha2"
	proxyv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha2"
	"go.f110.dev/heimdallr/pkg/config"
)

var EtcdClusterBase = EtcdClusterFactory(nil, EtcdVersion("v3.4.3"), HighAvailability)

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

func Backup(bucket string) EtcdClusterTrait {
	return func(e *etcdv1alpha2.EtcdCluster) {
		e.Spec.Backup = &etcdv1alpha2.BackupSpec{
			IntervalInSecond: 60,
			MaxBackups:       5,
			Storage: etcdv1alpha2.BackupStorageSpec{
				MinIO: &etcdv1alpha2.BackupStorageMinIOSpec{
					Bucket: bucket,
					Path:   "restore-test",
					ServiceSelector: etcdv1alpha2.ObjectSelector{
						Name:      "minio",
						Namespace: metav1.NamespaceDefault,
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

func Name(v string) EtcdClusterTrait {
	return func(e *etcdv1alpha2.EtcdCluster) {
		e.SetName(v)
	}
}

func EtcdVersion(v string) EtcdClusterTrait {
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

type EtcdClusterTrait func(e *etcdv1alpha2.EtcdCluster)

func EtcdClusterFactory(base *etcdv1alpha2.EtcdCluster, traits ...EtcdClusterTrait) *etcdv1alpha2.EtcdCluster {
	var e *etcdv1alpha2.EtcdCluster
	if base == nil {
		e = &etcdv1alpha2.EtcdCluster{}
	} else {
		e = base
	}

	for _, trait := range traits {
		trait(e)
	}

	setObjectMeta(e)
	return e
}

func setObjectMeta(obj metav1.Object) {
	if obj.GetName() == "" {
		obj.SetName("noname")
	}
	if obj.GetNamespace() == "" {
		obj.SetNamespace(metav1.NamespaceDefault)
	}
}

var ProxyBase = ProxyFactory(&proxyv1alpha2.Proxy{
	Spec: proxyv1alpha2.ProxySpec{
		Development: true,
		Domain:      "e2e.f110.dev",
		Replicas:    3,
		CertificateAuthority: &proxyv1alpha2.CertificateAuthoritySpec{
			Local: &proxyv1alpha2.LocalCertificateAuthoritySpec{
				Name: "e2e",
			},
		},
		BackendSelector: proxyv1alpha2.LabelSelector{
			LabelSelector: metav1.LabelSelector{},
		},
		IdentityProvider: proxyv1alpha2.IdentityProviderSpec{
			Provider: "google",
			ClientId: "e2e",
		},
		IssuerRef: certmanagermetav1.ObjectReference{
			Kind: "ClusterIssuer",
			Name: "self-signed",
		},
	},
}, EtcdDataStore, CookieSession)

type ProxyTrait func(p *proxyv1alpha2.Proxy)

func ProxyFactory(base *proxyv1alpha2.Proxy, traits ...ProxyTrait) *proxyv1alpha2.Proxy {
	var p *proxyv1alpha2.Proxy
	if base == nil {
		p = &proxyv1alpha2.Proxy{}
	} else {
		p = base
	}

	for _, trait := range traits {
		trait(p)
	}

	setObjectMeta(p)
	return p
}

func EtcdDataStore(p *proxyv1alpha2.Proxy) {
	p.Spec.DataStore = &proxyv1alpha2.ProxyDataStoreSpec{
		Etcd: &proxyv1alpha2.ProxyDataStoreEtcdSpec{
			Version:      "v3.4.8",
			AntiAffinity: true,
		},
	}
}

func ClientSecret(name, key string) ProxyTrait {
	return func(p *proxyv1alpha2.Proxy) {
		p.Spec.IdentityProvider.ClientSecretRef.Name = name
		p.Spec.IdentityProvider.ClientSecretRef.Key = key
	}
}

func RootUsers(users []string) ProxyTrait {
	return func(p *proxyv1alpha2.Proxy) {
		p.Spec.RootUsers = users
	}
}

func ProxyVersion(v string) ProxyTrait {
	return func(p *proxyv1alpha2.Proxy) {
		p.Spec.Version = v
	}
}

func CookieSession(e *proxyv1alpha2.Proxy) {
	e.Spec.Session = proxyv1alpha2.SessionSpec{
		Type: config.SessionTypeSecureCookie,
	}
}
