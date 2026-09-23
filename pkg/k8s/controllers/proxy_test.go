package controllers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/pkg/config/configv2"

	"go.f110.dev/heimdallr/pkg/k8s/api/etcdv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxy"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxyv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
)

func (r *HeimdallrProxy) PrepareCompleted(ec *etcdv1alpha2.EtcdCluster) []runtime.Object {
	obj := []runtime.Object{
		r.Certificate(),
		k8sfactory.SecretFactory(nil,
			k8sfactory.Name(ec.Status.ClientCertSecretName),
			k8sfactory.Namespace(r.Namespace),
			k8sfactory.Data("ca.crt", []byte("")),
			k8sfactory.Data("client.crt", []byte("")),
			k8sfactory.Data("client.key", []byte("")),
		),
		k8sfactory.SecretFactory(nil,
			k8sfactory.Name(r.CertificateSecretName()),
			k8sfactory.Namespace(r.Namespace),
			k8sfactory.Data("ca.crt", []byte("")),
			k8sfactory.Data("client.crt", []byte("")),
			k8sfactory.Data("client.key", []byte("")),
		),
	}
	for _, v := range r.DefaultBackends() {
		obj = append(obj, v)
	}
	for _, v := range r.DefaultRoles() {
		obj = append(obj, v)
	}
	for _, v := range r.DefaultRoleBindings() {
		obj = append(obj, v)
	}
	for _, v := range r.DefaultRpcPermissions() {
		obj = append(obj, v)
	}

	return obj
}

func TestHeimdallrProxy_EtcdCluster(t *testing.T) {
	t.Run("MinIO", func(t *testing.T) {
		p := proxy.Factory(nil,
			proxy.EtcdDataStore,
			proxy.EtcdBackup(600, 100),
			proxy.EtcdBackupToMinIO(
				"test-bucket",
				"test-path",
				true,
				"test",
				"test",
				&proxyv1alpha2.AWSCredentialSelector{
					Name:               "aws",
					Namespace:          "default",
					AccessKeyIDKey:     "accesskey",
					SecretAccessKeyKey: "secretkey",
				},
			),
		)
		hp := NewHeimdallrProxy(HeimdallrProxyParams{Spec: p})

		etcdC, podMonitor := hp.EtcdCluster()
		require.NotNil(t, etcdC)
		require.Nil(t, podMonitor)
		require.NotNil(t, etcdC.Spec.Backup)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.IntervalInSeconds, etcdC.Spec.Backup.IntervalInSeconds)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.MaxBackups, etcdC.Spec.Backup.MaxBackups)
		require.NotNil(t, etcdC.Spec.Backup.Storage.MinIO)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.MinIO.Bucket, etcdC.Spec.Backup.Storage.MinIO.Bucket)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.MinIO.Path, etcdC.Spec.Backup.Storage.MinIO.Path)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.MinIO.Secure, etcdC.Spec.Backup.Storage.MinIO.Secure)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.MinIO.CredentialSelector.Name, etcdC.Spec.Backup.Storage.MinIO.CredentialSelector.Name)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.MinIO.CredentialSelector.Namespace, etcdC.Spec.Backup.Storage.MinIO.CredentialSelector.Namespace)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.MinIO.CredentialSelector.AccessKeyIDKey, etcdC.Spec.Backup.Storage.MinIO.CredentialSelector.AccessKeyIDKey)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.MinIO.CredentialSelector.SecretAccessKeyKey, etcdC.Spec.Backup.Storage.MinIO.CredentialSelector.SecretAccessKeyKey)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.MinIO.ServiceSelector.Name, etcdC.Spec.Backup.Storage.MinIO.ServiceSelector.Name)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.MinIO.ServiceSelector.Namespace, etcdC.Spec.Backup.Storage.MinIO.ServiceSelector.Namespace)
	})

	t.Run("GCS", func(t *testing.T) {
		p := proxy.Factory(nil,
			proxy.EtcdDataStore,
			proxy.EtcdBackup(600, 100),
			proxy.EtcdBackupToGCS(
				"test",
				"test-path",
				&proxyv1alpha2.GCPCredentialSelector{
					Name:                  "gcp",
					Namespace:             "gcs",
					ServiceAccountJSONKey: "account.json",
				},
			),
		)
		hp := NewHeimdallrProxy(HeimdallrProxyParams{Spec: p})

		etcdC, podMonitor := hp.EtcdCluster()
		require.NotNil(t, etcdC)
		require.Nil(t, podMonitor)
		require.NotNil(t, etcdC.Spec.Backup)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.IntervalInSeconds, etcdC.Spec.Backup.IntervalInSeconds)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.MaxBackups, etcdC.Spec.Backup.MaxBackups)
		require.NotNil(t, etcdC.Spec.Backup.Storage.GCS)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.GCS.Bucket, etcdC.Spec.Backup.Storage.GCS.Bucket)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.GCS.Path, etcdC.Spec.Backup.Storage.GCS.Path)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.GCS.CredentialSelector.Name, etcdC.Spec.Backup.Storage.GCS.CredentialSelector.Name)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.GCS.CredentialSelector.Namespace, etcdC.Spec.Backup.Storage.GCS.CredentialSelector.Namespace)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.GCS.CredentialSelector.ServiceAccountJSONKey, etcdC.Spec.Backup.Storage.GCS.CredentialSelector.ServiceAccountJSONKey)
	})
}

func TestHeimdallrProxy_TokenExpiration(t *testing.T) {
	p := proxy.Factory(nil, proxy.EtcdDataStore, proxy.IdentityProvider("google", "client-id", "client-secret", "secret"), proxy.CookieSession)
	p.Spec.TokenExpiration = &metav1.Duration{Duration: int64(time.Hour)}
	hp := NewHeimdallrProxy(HeimdallrProxyParams{Spec: p})
	hp.Datastore = &etcdv1alpha2.EtcdCluster{Status: etcdv1alpha2.EtcdClusterStatus{ClientEndpoint: "https://etcd.example.com:2379"}}

	for name, fn := range map[string]func() (*corev1.ConfigMap, error){
		"Main":      hp.ConfigForMain,
		"RPCServer": hp.ConfigForRPCServer,
	} {
		t.Run(name, func(t *testing.T) {
			configMap, err := fn()
			require.NoError(t, err)

			conf := &configv2.Config{}
			require.NoError(t, yaml.Unmarshal([]byte(configMap.Data[configFilename]), conf))
			assert.Equal(t, time.Hour, conf.AccessProxy.GetTokenExpiration())
		})
	}
}
