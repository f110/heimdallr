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

	"go.f110.dev/heimdallr/operator/pkg/api/etcd"
	"go.f110.dev/heimdallr/operator/pkg/api/proxy"
	proxyv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha2"
	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
)

func newProxy(name string) (*proxyv1alpha2.Proxy, *corev1.Secret, []*proxyv1alpha2.Backend, []*proxyv1alpha2.Role, []*proxyv1alpha2.RpcPermission, []*proxyv1alpha2.RoleBinding, []*corev1.Service) {
	p := proxy.Factory(nil,
		k8sfactory.Name(name),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.UID(),
		proxy.Domain("test-proxy.f110.dev"),
		proxy.EtcdDataStore,
		proxy.EnableAntiAffinity,
		proxy.EtcdBackup(24*60, 5),
		proxy.EtcdBackupToMinIO(
			"test",
			"bucket-test",
			false,
			"minio",
			metav1.NamespaceDefault,
			proxyv1alpha2.AWSCredentialSelector{
				Name:               "minio-token",
				Namespace:          metav1.NamespaceDefault,
				AccessKeyIDKey:     "accesskey",
				SecretAccessKeyKey: "secretkey",
			},
		),
		proxy.BackendMatchLabelSelector(metav1.NamespaceAll, map[string]string{"instance": "test"}),
		proxy.RoleMatchLabelSelector(metav1.NamespaceAll, map[string]string{"instance": "test"}),
		proxy.RpcPermissionMatchLabelSelector(metav1.NamespaceAll, map[string]string{"instance": "test"}),
		proxy.CookieSession,
		proxy.IdentityProvider("google", "client-id", "client-secret", "client-secret"),
	)

	clientSecret := k8sfactory.SecretFactory(nil,
		k8sfactory.Name("client-secret"),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.Data("client-secret", []byte("hidden")),
	)

	backend := proxy.BackendFactory(nil,
		k8sfactory.Name("test"),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.Created,
		k8sfactory.Label("instance", "test"),
		proxy.Layer("test"),
		proxy.HTTP([]*proxyv1alpha2.BackendHTTPSpec{
			{
				Path: "/",
				ServiceSelector: &proxyv1alpha2.ServiceSelector{
					LabelSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "test"},
					},
				},
			},
		}),
		proxy.Permission(proxy.PermissionFactory(nil,
			proxy.Name("all"),
			proxy.Location("Any", "/"),
		)),
	)
	backends := []*proxyv1alpha2.Backend{backend}

	role := proxy.RoleFactory(nil,
		k8sfactory.Name("test"),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.Created,
		k8sfactory.Label("instance", "test"),
		proxy.Title("test"),
		proxy.Description("for testing"),
	)
	roles := []*proxyv1alpha2.Role{role}
	rpcPermissions := []*proxyv1alpha2.RpcPermission{}
	roleBindings := []*proxyv1alpha2.RoleBinding{
		proxy.RoleBindingFactory(nil,
			k8sfactory.Name("test-test"),
			k8sfactory.Namespace(metav1.NamespaceDefault),
			k8sfactory.Created,
			proxy.Role(role),
			proxy.Subject(backend, "all"),
		),
	}

	services := []*corev1.Service{
		k8sfactory.ServiceFactory(nil,
			k8sfactory.Name("test-backend-svc"),
			k8sfactory.Namespace(metav1.NamespaceDefault),
			k8sfactory.Label("app", "test"),
			k8sfactory.Port("http", corev1.ProtocolTCP, 80),
		),
	}

	return p, clientSecret, backends, roles, rpcPermissions, roleBindings, services
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

		hp := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec:           p,
			Clientset:      f.client,
			ServiceLister:  f.c.serviceLister,
			Backends:       backends,
			Roles:          roles,
			RpcPermissions: rpcPermissions,
			RoleBindings:   roleBindings,
		})

		for _, v := range hp.Secrets() {
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

		hp := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec:           p,
			Clientset:      f.client,
			ServiceLister:  f.c.serviceLister,
			Backends:       backends,
			Roles:          roles,
			RpcPermissions: rpcPermissions,
			RoleBindings:   roleBindings,
		})
		ec, _ := hp.EtcdCluster()
		ec = etcd.Factory(ec, etcd.Ready)
		f.RegisterEtcdClusterFixture(ec)
		for _, v := range hp.Secrets() {
			s, err := v.Create()
			hp.ControlObject(s)

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

		hp := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec:           p,
			Clientset:      f.client,
			ServiceLister:  f.c.serviceLister,
			Backends:       backends,
			Roles:          roles,
			RpcPermissions: rpcPermissions,
			RoleBindings:   roleBindings,
		})
		ec, _ := hp.EtcdCluster()
		f.RegisterEtcdClusterFixture(ec)
		for _, v := range hp.Secrets() {
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

		hp := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec:           p,
			Clientset:      f.client,
			ServiceLister:  f.c.serviceLister,
			Backends:       backends,
			Roles:          roles,
			RpcPermissions: rpcPermissions,
			RoleBindings:   roleBindings,
		})
		ec, _ := hp.EtcdCluster()
		ec = etcd.Factory(ec, etcd.Ready)
		f.RegisterEtcdClusterFixture(ec)
		for _, v := range hp.Secrets() {
			s, err := v.Create()
			if err != nil {
				t.Fatal(err)
			}
			f.RegisterSecretFixture(s)
		}
		f.RegisterProxyFixture(p)
		f.RegisterFixtures(hp.PrepareCompleted(ec)...)

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
		proxyConfigMap, err := f.coreClient.CoreV1().ConfigMaps(hp.Namespace).Get(context.TODO(), hp.ReverseProxyConfigName(), metav1.GetOptions{})
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
			f.RegisterServiceFixture(s)
		}
		f.RegisterSecretFixture(clientSecret)

		hp := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec:           p,
			Clientset:      f.client,
			ServiceLister:  f.c.serviceLister,
			Backends:       backends,
			Roles:          roles,
			RpcPermissions: rpcPermissions,
			RoleBindings:   roleBindings,
		})
		ec, _ := hp.EtcdCluster()
		ec = etcd.Factory(ec, etcd.Ready)
		f.RegisterFixtures(hp.PrepareCompleted(ec)...)
		hp.Datastore = ec
		f.RegisterEtcdClusterFixture(ec)
		for _, v := range hp.Secrets() {
			s, err := v.Create()
			require.NoError(t, err)
			f.RegisterSecretFixture(s)
		}
		f.RegisterProxyFixture(p)
		err := hp.Init(f.coreSharedInformerFactory.Core().V1().Secrets().Lister())
		require.NoError(t, err)
		pcs, err := hp.IdealRPCServer()
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
