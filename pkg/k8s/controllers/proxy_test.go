package controllers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"

	etcdv1alpha2 "go.f110.dev/heimdallr/pkg/k8s/api/etcd/v1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxy"
	proxyv1alpha2 "go.f110.dev/heimdallr/pkg/k8s/api/proxy/v1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
)

func (r *HeimdallrProxy) PrepareCompleted(ec *etcdv1alpha2.EtcdCluster) []runtime.Object {
	return []runtime.Object{
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
				proxyv1alpha2.AWSCredentialSelector{
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
		require.NotNil(t, podMonitor)
		require.NotNil(t, etcdC.Spec.Backup)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.IntervalInSecond, etcdC.Spec.Backup.IntervalInSecond)
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
				proxyv1alpha2.GCPCredentialSelector{
					Name:                  "gcp",
					Namespace:             "gcs",
					ServiceAccountJSONKey: "account.json",
				},
			),
		)
		hp := NewHeimdallrProxy(HeimdallrProxyParams{Spec: p})

		etcdC, podMonitor := hp.EtcdCluster()
		require.NotNil(t, etcdC)
		require.NotNil(t, podMonitor)
		require.NotNil(t, etcdC.Spec.Backup)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.IntervalInSecond, etcdC.Spec.Backup.IntervalInSecond)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.MaxBackups, etcdC.Spec.Backup.MaxBackups)
		require.NotNil(t, etcdC.Spec.Backup.Storage.GCS)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.GCS.Bucket, etcdC.Spec.Backup.Storage.GCS.Bucket)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.GCS.Path, etcdC.Spec.Backup.Storage.GCS.Path)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.GCS.CredentialSelector.Name, etcdC.Spec.Backup.Storage.GCS.CredentialSelector.Name)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.GCS.CredentialSelector.Namespace, etcdC.Spec.Backup.Storage.GCS.CredentialSelector.Namespace)
		assert.Equal(t, hp.Spec.DataStore.Etcd.Backup.Storage.GCS.CredentialSelector.ServiceAccountJSONKey, etcdC.Spec.Backup.Storage.GCS.CredentialSelector.ServiceAccountJSONKey)
	})
}
