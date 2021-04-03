package controllers

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"

	"go.f110.dev/heimdallr/operator/pkg/api/etcd"
	proxyv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha2"
	"go.f110.dev/heimdallr/pkg/config"
)

func newProxy(name string) (*proxyv1alpha2.Proxy, *corev1.Secret, []*proxyv1alpha2.Backend, []*proxyv1alpha2.Role, []*proxyv1alpha2.RpcPermission, []*proxyv1alpha2.RoleBinding, []corev1.Service) {
	proxy := &proxyv1alpha2.Proxy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceDefault,
			UID:       uuid.NewUUID(),
		},
		Spec: proxyv1alpha2.ProxySpec{
			Domain: "test-proxy.f110.dev",
			DataStore: &proxyv1alpha2.ProxyDataStoreSpec{
				Etcd: &proxyv1alpha2.ProxyDataStoreEtcdSpec{
					Version: "v3.4.9",
					Backup: &proxyv1alpha2.EtcdBackupSpec{
						IntervalInSecond: 24 * 60,
						MaxBackups:       5,
						Storage: proxyv1alpha2.EtcdBackupStorageSpec{
							MinIO: &proxyv1alpha2.EtcdBackupMinIOSpec{
								ServiceSelector: proxyv1alpha2.ObjectSelector{
									Name:      "minio",
									Namespace: metav1.NamespaceDefault,
								},
								CredentialSelector: proxyv1alpha2.AWSCredentialSelector{
									Name:               "minio-token",
									Namespace:          metav1.NamespaceDefault,
									AccessKeyIDKey:     "accesskey",
									SecretAccessKeyKey: "secretkey",
								},
								Bucket: "test",
								Path:   "backup-test",
								Secure: false,
							},
						},
					},
				},
			},
			BackendSelector: proxyv1alpha2.LabelSelector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"instance": "test"},
				},
			},
			RoleSelector: proxyv1alpha2.LabelSelector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"instance": "test"},
				},
			},
			RpcPermissionSelector: proxyv1alpha2.LabelSelector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"instance": "test"},
				},
			},
			Session: proxyv1alpha2.SessionSpec{
				Type: config.SessionTypeSecureCookie,
			},
			IdentityProvider: proxyv1alpha2.IdentityProviderSpec{
				Provider: "google",
				ClientSecretRef: proxyv1alpha2.SecretSelector{
					Name: "client-secret",
					Key:  "client-secret",
				},
			},
		},
	}

	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "client-secret",
			Namespace: metav1.NamespaceDefault,
		},
		Data: map[string][]byte{"client-secret": []byte("hidden")},
	}

	backends := []*proxyv1alpha2.Backend{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "test",
				Namespace:         metav1.NamespaceDefault,
				CreationTimestamp: metav1.Now(),
				Labels:            map[string]string{"instance": "test"},
			},
			Spec: proxyv1alpha2.BackendSpec{
				Layer: "test",
				HTTP: []*proxyv1alpha2.BackendHTTPSpec{
					{
						Path: "/",
						ServiceSelector: &proxyv1alpha2.ServiceSelector{
							LabelSelector: metav1.LabelSelector{
								MatchLabels: map[string]string{"app": "test"},
							},
						},
					},
				},
				Permissions: []proxyv1alpha2.Permission{
					{Name: "all", Locations: []proxyv1alpha2.Location{{Any: "/"}}},
				},
			},
		},
	}

	roles := []*proxyv1alpha2.Role{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "test",
				Namespace:         metav1.NamespaceDefault,
				CreationTimestamp: metav1.Now(),
				Labels:            map[string]string{"instance": "test"},
			},
			Spec: proxyv1alpha2.RoleSpec{
				Title:       "test",
				Description: "for testing",
			},
		},
	}
	rpcPermissions := []*proxyv1alpha2.RpcPermission{}
	roleBindings := []*proxyv1alpha2.RoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "test-test",
				Namespace:         metav1.NamespaceDefault,
				CreationTimestamp: metav1.Now(),
			},
			Subjects: []proxyv1alpha2.Subject{
				{Kind: "Backend", Name: "test", Namespace: metav1.NamespaceDefault, Permission: "all"},
			},
			RoleRef: proxyv1alpha2.RoleRef{
				Name:      "test",
				Namespace: metav1.NamespaceDefault,
			},
		},
	}

	services := []corev1.Service{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-backend-svc",
				Namespace: metav1.NamespaceDefault,
				Labels:    map[string]string{"app": "test"},
			},
			Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{
					{Name: "http", Port: 80},
				},
			},
		},
	}

	return proxy, clientSecret, backends, roles, rpcPermissions, roleBindings, services
}

func registerFixtureFromProcess(f *proxyControllerTestRunner, p *process) {
	if p.Deployment != nil {
		f.RegisterDeploymentFixture(p.Deployment)
	}

	if p.Service != nil {
		for _, v := range p.Service {
			f.RegisterServiceFixture(v)
		}
	}

	if p.ConfigMaps != nil {
		f.RegisterConfigMapFixture(p.ConfigMaps...)
	}

	if p.PodDisruptionBudget != nil {
		f.RegisterPodDisruptionBudgetFixture(p.PodDisruptionBudget)
	}
}

func TestProxyController(t *testing.T) {
	t.Run("NewProxyController", func(t *testing.T) {
		t.Parallel()

		f := newProxyControllerTestRunner(t)

		p, clientSecret, backends, roles, rpcPermissions, roleBindings, _ := newProxy("test")
		f.RegisterProxyFixture(p)
		f.RegisterSecretFixture(clientSecret)

		proxy := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec:           p,
			Clientset:      f.client,
			ServiceLister:  f.c.serviceLister,
			Backends:       backends,
			Roles:          roles,
			RpcPermissions: rpcPermissions,
			RoleBindings:   roleBindings,
		})

		for _, v := range proxy.Secrets() {
			_, err := v.Create()
			if err != nil {
				t.Fatal(err)
			}
			f.ExpectCreateSecret()
		}
		f.ExpectUpdateProxyStatus()
		f.ExpectCreateCertificate()

		f.Run(t, p)
	})

	t.Run("Remove ownerReference in Secret", func(t *testing.T) {
		t.Parallel()

		f := newProxyControllerTestRunner(t)

		p, clientSecret, backends, roles, rpcPermissions, roleBindings, _ := newProxy("test")
		p.Status.CASecretName = p.Name + "-ca"
		f.RegisterProxyFixture(p)
		f.RegisterSecretFixture(clientSecret)
		f.RegisterBackendFixture(backends...)

		proxy := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec:           p,
			Clientset:      f.client,
			ServiceLister:  f.c.serviceLister,
			Backends:       backends,
			Roles:          roles,
			RpcPermissions: rpcPermissions,
			RoleBindings:   roleBindings,
		})
		ec, _ := proxy.EtcdCluster()
		ec = etcd.Factory(ec, etcd.Ready)
		f.RegisterEtcdClusterFixture(ec)
		for _, v := range proxy.Secrets() {
			s, err := v.Create()
			proxy.ControlObject(s)

			require.NoError(t, err)
			f.RegisterSecretFixture(s)
		}

		f.ExpectUpdateProxyStatus()
		f.ExpectUpdateSecret()
		f.ExpectCreateCertificate()
		f.Run(t, p)

		caSecret, err := f.coreClient.CoreV1().Secrets(p.Namespace).Get(context.TODO(), p.Status.CASecretName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Len(t, caSecret.OwnerReferences, 0)
	})

	t.Run("Preparing phase when EtcdCluster is not ready", func(t *testing.T) {
		t.Parallel()

		f := newProxyControllerTestRunner(t)

		p, clientSecret, backends, roles, rpcPermissions, roleBindings, _ := newProxy("test")
		f.RegisterProxyFixture(p)
		f.RegisterSecretFixture(clientSecret)

		proxy := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec:           p,
			Clientset:      f.client,
			ServiceLister:  f.c.serviceLister,
			Backends:       backends,
			Roles:          roles,
			RpcPermissions: rpcPermissions,
			RoleBindings:   roleBindings,
		})
		ec, _ := proxy.EtcdCluster()
		f.RegisterEtcdClusterFixture(ec)
		for _, v := range proxy.Secrets() {
			s, err := v.Create()
			require.NoError(t, err)
			f.RegisterSecretFixture(s)
		}

		f.ExpectUpdateProxyStatus()
		f.ExpectCreateCertificate()
		f.Run(t, p)

		etcdC, err := f.client.EtcdV1alpha2().EtcdClusters(ec.Namespace).Get(context.TODO(), ec.Name, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, p.Spec.DataStore.Etcd.Version, etcdC.Spec.Version)
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

	t.Run("Finish preparing phase", func(t *testing.T) {
		t.Parallel()

		f := newProxyControllerTestRunner(t)

		p, clientSecret, backends, roles, rpcPermissions, roleBindings, _ := newProxy("test")
		f.RegisterProxyFixture(p)
		f.RegisterBackendFixture(backends...)
		f.RegisterProxyRoleFixture(roles...)
		f.RegisterProxyRoleBindingFixture(roleBindings...)
		f.RegisterSecretFixture(clientSecret)

		proxy := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec:           p,
			Clientset:      f.client,
			ServiceLister:  f.c.serviceLister,
			Backends:       backends,
			Roles:          roles,
			RpcPermissions: rpcPermissions,
			RoleBindings:   roleBindings,
		})
		ec, _ := proxy.EtcdCluster()
		ec = etcd.Factory(ec, etcd.Ready)
		f.RegisterEtcdClusterFixture(ec)
		for _, v := range proxy.Secrets() {
			s, err := v.Create()
			if err != nil {
				t.Fatal(err)
			}
			f.RegisterSecretFixture(s)
		}
		f.RegisterProxyFixture(p)
		f.RegisterFixtures(proxy.PrepareCompleted(ec)...)

		f.ExpectUpdateProxyStatus()
		f.ExpectCreateDeployment()
		f.ExpectCreatePodDisruptionBudget()
		f.ExpectCreateService()
		f.ExpectCreateConfigMap()
		f.ExpectCreateConfigMap()
		f.ExpectUpdateProxyStatus()
		f.Run(t, p)

		updatedP, err := f.client.ProxyV1alpha2().Proxies(p.Namespace).Get(context.TODO(), p.Name, metav1.GetOptions{})
		require.NoError(t, err)
		proxyConfigMap, err := f.coreClient.CoreV1().ConfigMaps(proxy.Namespace).Get(context.TODO(), proxy.ReverseProxyConfigName(), metav1.GetOptions{})
		require.NoError(t, err)

		assert.NotEmpty(t, updatedP.Status.CASecretName)
		assert.NotEmpty(t, updatedP.Status.SigningPrivateKeySecretName)
		assert.NotEmpty(t, updatedP.Status.GithubWebhookSecretName)
		assert.NotEmpty(t, updatedP.Status.InternalTokenSecretName)
		assert.NotEmpty(t, updatedP.Status.CookieSecretName)

		assert.NotEmpty(t, proxyConfigMap.Data[proxyFilename])
		assert.NotEmpty(t, proxyConfigMap.Data[roleFilename])
		assert.NotEmpty(t, proxyConfigMap.Data[rpcPermissionFilename])

		roleConfig := make([]*config.Role, 0)
		if err := yaml.Unmarshal([]byte(proxyConfigMap.Data[roleFilename]), &roleConfig); err != nil {
			t.Fatal(err)
		}
		roleMap := make(map[string]*config.Role)
		for _, v := range roleConfig {
			roleMap[v.Name] = v
		}
		assert.Len(t, roleConfig, 2)
		assert.Contains(t, roleMap, "test")
		assert.Contains(t, roleMap, "admin")
		assert.Len(t, roleMap["test"].Bindings, 1)
		assert.Len(t, roleMap["admin"].Bindings, 1)
	})

	t.Run("RPC server is ready", func(t *testing.T) {
		t.Parallel()

		f := newProxyControllerTestRunner(t)

		p, clientSecret, backends, roles, rpcPermissions, roleBindings, services := newProxy("test")
		f.RegisterProxyFixture(p)
		f.RegisterBackendFixture(backends...)
		f.RegisterProxyRoleFixture(roles...)
		f.RegisterProxyRoleBindingFixture(roleBindings...)
		for _, s := range services {
			f.RegisterServiceFixture(&s)
		}
		f.RegisterSecretFixture(clientSecret)

		proxy := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec:           p,
			Clientset:      f.client,
			ServiceLister:  f.c.serviceLister,
			Backends:       backends,
			Roles:          roles,
			RpcPermissions: rpcPermissions,
			RoleBindings:   roleBindings,
		})
		ec, _ := proxy.EtcdCluster()
		ec = etcd.Factory(ec, etcd.Ready)
		f.RegisterFixtures(proxy.PrepareCompleted(ec)...)
		proxy.Datastore = ec
		f.RegisterEtcdClusterFixture(ec)
		for _, v := range proxy.Secrets() {
			s, err := v.Create()
			require.NoError(t, err)
			f.RegisterSecretFixture(s)
		}
		f.RegisterProxyFixture(p)
		err := proxy.Init(f.coreSharedInformerFactory.Core().V1().Secrets().Lister())
		require.NoError(t, err)
		pcs, err := proxy.IdealRPCServer()
		require.NoError(t, err)
		pcs.Deployment.Status.ReadyReplicas = *pcs.Deployment.Spec.Replicas
		registerFixtureFromProcess(f, pcs)

		f.ExpectUpdateProxyStatus()
		// Expect to create the proxy
		f.ExpectCreateDeployment()
		f.ExpectCreatePodDisruptionBudget()
		f.ExpectCreateService()
		f.ExpectCreateService()
		f.ExpectCreateConfigMap()
		f.ExpectUpdateProxyStatus()
		f.ExpectUpdateBackendStatus()
		// Expect to create the dashboard
		f.ExpectCreateDeployment()
		f.ExpectCreatePodDisruptionBudget()
		f.ExpectCreateService()
		f.ExpectCreateConfigMap()
		// Finally, update the status of proxy
		f.ExpectUpdateProxyStatus()
		f.Run(t, p)

		updatedP, err := f.client.ProxyV1alpha2().Proxies(p.Namespace).Get(context.TODO(), p.Name, metav1.GetOptions{})
		require.NoError(t, err)
		assert.False(t, updatedP.Status.Ready)
		assert.Equal(t, updatedP.Status.Phase, proxyv1alpha2.ProxyPhaseRunning)

		for _, backend := range backends {
			updatedB, err := f.client.ProxyV1alpha2().Backends(backend.Namespace).Get(context.TODO(), backend.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			assert.NotEmpty(t, updatedB.Status.DeployedBy)
			assert.Equal(t, updatedB.Status.DeployedBy[0].Name, p.Name)
			assert.Equal(t, updatedB.Status.DeployedBy[0].Namespace, p.Namespace)
			assert.Equal(t, updatedB.Status.DeployedBy[0].Url, fmt.Sprintf("https://%s.%s.%s", backend.Name, backend.Spec.Layer, p.Spec.Domain))
		}
	})
}
