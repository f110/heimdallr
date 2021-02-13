package controllers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	proxyv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha2"
)

func TestHeimdallrProxy_EtcdCluster(t *testing.T) {
	t.Run("MinIO", func(t *testing.T) {
		p := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec: &proxyv1alpha2.Proxy{
				Spec: proxyv1alpha2.ProxySpec{
					DataStore: &proxyv1alpha2.ProxyDataStoreSpec{
						Etcd: &proxyv1alpha2.ProxyDataStoreEtcdSpec{
							Backup: &proxyv1alpha2.EtcdBackupSpec{
								IntervalInSecond: 600,
								MaxBackups:       100,
								Storage: proxyv1alpha2.EtcdBackupStorageSpec{
									MinIO: &proxyv1alpha2.EtcdBackupMinIOSpec{
										ServiceSelector: proxyv1alpha2.ObjectSelector{
											Name:      "test",
											Namespace: "test",
										},
										CredentialSelector: proxyv1alpha2.AWSCredentialSelector{
											Name:               "aws",
											Namespace:          "default",
											AccessKeyIDKey:     "accesskey",
											SecretAccessKeyKey: "secretkey",
										},
										Bucket: "test-bucket",
										Path:   "test-path",
										Secure: true,
									},
								},
							},
						},
					},
				},
			},
		})

		etcdC, podMonitor := p.EtcdCluster()
		require.NotNil(t, etcdC)
		require.NotNil(t, podMonitor)
		require.NotNil(t, etcdC.Spec.Backup)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.IntervalInSecond, etcdC.Spec.Backup.IntervalInSecond)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.MaxBackups, etcdC.Spec.Backup.MaxBackups)
		require.NotNil(t, etcdC.Spec.Backup.Storage.MinIO)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.Storage.MinIO.Bucket, etcdC.Spec.Backup.Storage.MinIO.Bucket)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.Storage.MinIO.Path, etcdC.Spec.Backup.Storage.MinIO.Path)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.Storage.MinIO.Secure, etcdC.Spec.Backup.Storage.MinIO.Secure)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.Storage.MinIO.CredentialSelector.Name, etcdC.Spec.Backup.Storage.MinIO.CredentialSelector.Name)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.Storage.MinIO.CredentialSelector.Namespace, etcdC.Spec.Backup.Storage.MinIO.CredentialSelector.Namespace)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.Storage.MinIO.CredentialSelector.AccessKeyIDKey, etcdC.Spec.Backup.Storage.MinIO.CredentialSelector.AccessKeyIDKey)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.Storage.MinIO.CredentialSelector.SecretAccessKeyKey, etcdC.Spec.Backup.Storage.MinIO.CredentialSelector.SecretAccessKeyKey)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.Storage.MinIO.ServiceSelector.Name, etcdC.Spec.Backup.Storage.MinIO.ServiceSelector.Name)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.Storage.MinIO.ServiceSelector.Namespace, etcdC.Spec.Backup.Storage.MinIO.ServiceSelector.Namespace)
	})

	t.Run("GCS", func(t *testing.T) {
		p := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec: &proxyv1alpha2.Proxy{
				Spec: proxyv1alpha2.ProxySpec{
					DataStore: &proxyv1alpha2.ProxyDataStoreSpec{
						Etcd: &proxyv1alpha2.ProxyDataStoreEtcdSpec{
							Backup: &proxyv1alpha2.EtcdBackupSpec{
								IntervalInSecond: 600,
								MaxBackups:       100,
								Storage: proxyv1alpha2.EtcdBackupStorageSpec{
									GCS: &proxyv1alpha2.EtcdBackupGCSSpec{
										Bucket: "test",
										Path:   "test-path",
										CredentialSelector: proxyv1alpha2.GCPCredentialSelector{
											Name:                  "gcp",
											Namespace:             "gcs",
											ServiceAccountJSONKey: "account.json",
										},
									},
								},
							},
						},
					},
				},
			},
		})

		etcdC, podMonitor := p.EtcdCluster()
		require.NotNil(t, etcdC)
		require.NotNil(t, podMonitor)
		require.NotNil(t, etcdC.Spec.Backup)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.IntervalInSecond, etcdC.Spec.Backup.IntervalInSecond)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.MaxBackups, etcdC.Spec.Backup.MaxBackups)
		require.NotNil(t, etcdC.Spec.Backup.Storage.GCS)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.Storage.GCS.Bucket, etcdC.Spec.Backup.Storage.GCS.Bucket)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.Storage.GCS.Path, etcdC.Spec.Backup.Storage.GCS.Path)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.Storage.GCS.CredentialSelector.Name, etcdC.Spec.Backup.Storage.GCS.CredentialSelector.Name)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.Storage.GCS.CredentialSelector.Namespace, etcdC.Spec.Backup.Storage.GCS.CredentialSelector.Namespace)
		assert.Equal(t, p.Spec.DataStore.Etcd.Backup.Storage.GCS.CredentialSelector.ServiceAccountJSONKey, etcdC.Spec.Backup.Storage.GCS.CredentialSelector.ServiceAccountJSONKey)
	})
}
