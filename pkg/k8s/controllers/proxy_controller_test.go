package controllers

import (
	"context"
	"fmt"
	"testing"

	certmanagerv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	listers "k8s.io/client-go/listers/core/v1"

	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/k8s/api/etcd"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxy"
	proxyv1alpha2 "go.f110.dev/heimdallr/pkg/k8s/api/proxy/v1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/client/versioned/fake"
	"go.f110.dev/heimdallr/pkg/k8s/controllers/controllertest"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
)

func TestProxyController(t *testing.T) {
	t.Run("NewProxyController", func(t *testing.T) {
		t.Parallel()

		runner, controller := newProxyController(t)

		p, clientSecret, backends, roles, rpcPermissions, roleBindings, _ := newProxy("test")
		registerFixtures(runner, clientSecret, backends, roles, rpcPermissions, roleBindings, nil)

		err := runner.Reconcile(controller, p)
		require.Error(t, err)
		controllertest.AssertRetry(t, err)

		namespace := k8sfactory.Namespace(p.Namespace)
		runner.AssertCreateAction(t, k8sfactory.SecretFactory(nil, k8sfactory.Namef("%s-ca", p.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.SecretFactory(nil, k8sfactory.Namef("%s-privkey", p.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.SecretFactory(nil, k8sfactory.Namef("%s-github-secret", p.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.SecretFactory(nil, k8sfactory.Namef("%s-cookie-secret", p.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.SecretFactory(nil, k8sfactory.Namef("%s-internal-token", p.Name), namespace))
		runner.AssertCreateAction(t, &certmanagerv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: p.Namespace,
			},
		})
		p.Status.Phase = proxyv1alpha2.ProxyPhaseCreating
		runner.AssertUpdateAction(t, "status", p)
		runner.AssertNoUnexpectedAction(t)
	})

	t.Run("Remove ownerReference in Secret", func(t *testing.T) {
		t.Parallel()

		runner, controller := newProxyController(t)

		p, clientSecret, backends, roles, rpcPermissions, roleBindings, _ := newProxy("test")
		p.Status.CASecretName = p.Name + "-ca"
		registerFixtures(runner, clientSecret, backends, roles, rpcPermissions, roleBindings, nil)

		hp := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec:           p,
			Clientset:      runner.Client,
			ServiceLister:  controller.serviceLister,
			Backends:       backends,
			Roles:          roles,
			RpcPermissions: rpcPermissions,
			RoleBindings:   roleBindings,
		})
		ec, _ := hp.EtcdCluster()
		ec = etcd.Factory(ec, etcd.Ready)
		runner.RegisterFixtures(ec)
		var caSecret *corev1.Secret
		for _, v := range hp.Secrets() {
			s, err := v.Create()
			hp.ControlObject(s)

			require.NoError(t, err)
			runner.RegisterFixtures(s)

			if v.Name == hp.CASecretName() {
				caSecret = s
			}
		}
		require.NotNil(t, caSecret)

		err := runner.Reconcile(controller, p)
		require.Error(t, err)
		controllertest.AssertRetry(t, err)

		p.Status.Phase = proxyv1alpha2.ProxyPhaseCreating
		runner.AssertUpdateAction(t, "status", p)
		runner.AssertUpdateAction(t, "", k8sfactory.SecretFactory(caSecret, k8sfactory.ClearOwnerReference))
		runner.AssertCreateAction(t, &certmanagerv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: p.Namespace,
			},
		})
		runner.AssertNoUnexpectedAction(t)

		caSecret, err = runner.CoreClient.CoreV1().Secrets(p.Namespace).Get(context.TODO(), p.Status.CASecretName, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Len(t, caSecret.OwnerReferences, 0)
	})

	t.Run("Preparing phase when EtcdCluster is not ready", func(t *testing.T) {
		t.Parallel()

		runner, controller := newProxyController(t)

		p, clientSecret, backends, roles, rpcPermissions, roleBindings, _ := newProxy("test")
		runner.RegisterFixtures(clientSecret)

		hp := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec:           p,
			Clientset:      runner.Client,
			ServiceLister:  controller.serviceLister,
			Backends:       backends,
			Roles:          roles,
			RpcPermissions: rpcPermissions,
			RoleBindings:   roleBindings,
		})
		runner.RegisterFixtures(k8sfactory.SecretFactory(nil, k8sfactory.Name(hp.CertificateSecretName()), k8sfactory.Namespace(p.Namespace)))
		ec, _ := hp.EtcdCluster()
		runner.RegisterFixtures(ec)
		for _, v := range hp.Secrets() {
			s, err := v.Create()
			require.NoError(t, err)
			runner.RegisterFixtures(s)
		}

		err := runner.Reconcile(controller, p)
		require.Error(t, err)
		controllertest.AssertRetry(t, err)

		p.Status.Phase = proxyv1alpha2.ProxyPhaseCreating
		runner.AssertUpdateAction(t, "status", p)
		runner.AssertCreateAction(t, &certmanagerv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: p.Namespace,
			},
		})
		runner.AssertCreateAction(t, &proxyv1alpha2.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-dashboard",
				Namespace: p.Namespace,
			},
		})
		runner.AssertCreateAction(t, &proxyv1alpha2.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-admin",
				Namespace: p.Namespace,
			},
		})
		runner.AssertCreateAction(t, &proxyv1alpha2.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-admin-dashboard",
				Namespace: p.Namespace,
			},
		})
		runner.AssertCreateAction(t, &proxyv1alpha2.RpcPermission{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-admin",
				Namespace: p.Namespace,
			},
		})
		runner.AssertNoUnexpectedAction(t)

		etcdC, err := runner.Client.EtcdV1alpha2().EtcdClusters(ec.Namespace).Get(context.TODO(), ec.Name, metav1.GetOptions{})
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

		runner, controller := newProxyController(t)

		p, clientSecret, backends, roles, rpcPermissions, roleBindings, _ := newProxy("test")
		registerFixtures(runner, clientSecret, backends, roles, rpcPermissions, roleBindings, nil)

		hp := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec:           p,
			Clientset:      runner.Client,
			ServiceLister:  controller.serviceLister,
			Backends:       backends,
			Roles:          roles,
			RpcPermissions: rpcPermissions,
			RoleBindings:   roleBindings,
		})
		ec, _ := hp.EtcdCluster()
		ec = etcd.Factory(ec, etcd.Ready)
		runner.RegisterFixtures(ec)
		for _, v := range hp.Secrets() {
			s, err := v.Create()
			require.NoError(t, err)
			runner.RegisterFixtures(s)
		}
		runner.RegisterFixtures(hp.PrepareCompleted(ec)...)

		err := runner.Reconcile(controller, p)
		require.Error(t, err)
		controllertest.AssertRetry(t, err)

		namespace := k8sfactory.Namespace(p.Namespace)
		runner.AssertUpdateAction(t, "status", proxy.Factory(p, proxy.Phase(proxyv1alpha2.ProxyPhaseCreating)))
		runner.AssertUpdateAction(t, "status", proxy.Factory(p, proxy.Phase(proxyv1alpha2.ProxyPhaseCreating), setProxyStatus))
		runner.AssertCreateAction(t, k8sfactory.DeploymentFactory(nil, k8sfactory.Namef("%s-rpcserver", p.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.PodDisruptionBudgetFactory(nil, k8sfactory.Namef("%s-rpcserver", p.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.ServiceFactory(nil, k8sfactory.Namef("%s-rpcserver", p.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.ConfigMapFactory(nil, k8sfactory.Namef("%s-rpcserver", p.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.ConfigMapFactory(nil, k8sfactory.Namef("%s-proxy", p.Name), namespace))
		runner.AssertNoUnexpectedAction(t)

		updatedP, err := runner.Client.ProxyV1alpha2().Proxies(p.Namespace).Get(context.TODO(), p.Name, metav1.GetOptions{})
		require.NoError(t, err)
		proxyConfigMap, err := runner.CoreClient.CoreV1().ConfigMaps(hp.Namespace).Get(context.TODO(), hp.ReverseProxyConfigName(), metav1.GetOptions{})
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
		assert.Contains(t, roleMap, "test-admin")
		assert.Len(t, roleMap["test"].Bindings, 1)
		assert.Len(t, roleMap["test-admin"].Bindings, 1)
	})

	t.Run("RPC server is ready", func(t *testing.T) {
		t.Parallel()

		runner, controller := newProxyController(t)

		p, clientSecret, backends, roles, rpcPermissions, roleBindings, services := newProxy("test")
		registerFixtures(runner, clientSecret, backends, roles, rpcPermissions, roleBindings, services)

		hp := newHeimdallrProxy(runner.Client, controller.serviceLister, p, backends, roles, roleBindings, rpcPermissions)
		ec, _ := hp.EtcdCluster()
		ec = etcd.Factory(ec, etcd.Ready)
		runner.RegisterFixtures(hp.PrepareCompleted(ec)...)
		hp.Datastore = ec
		runner.RegisterFixtures(ec)
		for _, v := range hp.Secrets() {
			s, err := v.Create()
			require.NoError(t, err)
			runner.RegisterFixtures(s)
		}
		err := hp.Init(runner.CoreSharedInformerFactory.Core().V1().Secrets().Lister())
		require.NoError(t, err)
		pcs, err := hp.IdealRPCServer()
		require.NoError(t, err)
		pcs.Deployment.Status.ReadyReplicas = *pcs.Deployment.Spec.Replicas
		registerFixtureFromProcess(runner, pcs)

		err = runner.Reconcile(controller, p)
		require.NoError(t, err)

		namespace := k8sfactory.Namespace(p.Namespace)
		runner.AssertUpdateAction(t, "status", proxy.Factory(p, proxy.Phase(proxyv1alpha2.ProxyPhaseCreating)))
		runner.AssertUpdateAction(t, "status", proxy.Factory(p, proxy.Phase(proxyv1alpha2.ProxyPhaseRunning), setProxyStatus, setProxyStatusNumberOf))
		runner.AssertCreateAction(t, k8sfactory.DeploymentFactory(nil, k8sfactory.Name(p.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.PodDisruptionBudgetFactory(nil, k8sfactory.Name(p.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.ServiceFactory(nil, k8sfactory.Name(p.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.ServiceFactory(nil, k8sfactory.Namef("%s-internal", p.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.ConfigMapFactory(nil, k8sfactory.Name(p.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.DeploymentFactory(nil, k8sfactory.Namef("%s-dashboard", p.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.PodDisruptionBudgetFactory(nil, k8sfactory.Namef("%s-dashboard", p.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.ServiceFactory(nil, k8sfactory.Namef("%s-dashboard", p.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.ConfigMapFactory(nil, k8sfactory.Namef("%s-dashboard", p.Name), namespace))
		updatedBackend := backends[0].DeepCopy()
		updatedBackend.Status.DeployedBy = []*proxyv1alpha2.ProxyReference{
			{Name: p.Name, Namespace: p.Namespace, Url: fmt.Sprintf("https://%s.%s.%s", updatedBackend.Name, updatedBackend.Spec.Layer, p.Spec.Domain)},
		}
		runner.AssertUpdateAction(t, "status", updatedBackend)
		updatedRole := roles[0].DeepCopy()
		updatedRole.Status.Backends = []string{"default/test/all"}
		runner.AssertUpdateAction(t, "status", updatedRole)
		updatedRole = hp.DefaultRoles()[0]
		updatedRole.Status.Backends = []string{"default/test-dashboard/all"}
		runner.AssertUpdateAction(t, "status", updatedRole)
		runner.AssertUpdateAction(t, "status", proxy.Factory(p, proxy.Phase(proxyv1alpha2.ProxyPhaseCreating), setProxyStatus, setProxyStatusNumberOf))
		runner.AssertNoUnexpectedAction(t)

		updatedP, err := runner.Client.ProxyV1alpha2().Proxies(p.Namespace).Get(context.TODO(), p.Name, metav1.GetOptions{})
		require.NoError(t, err)
		assert.False(t, updatedP.Status.Ready)
		assert.Equal(t, updatedP.Status.Phase, proxyv1alpha2.ProxyPhaseRunning)

		for _, backend := range backends {
			updatedB, err := runner.Client.ProxyV1alpha2().Backends(backend.Namespace).Get(context.TODO(), backend.Name, metav1.GetOptions{})
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

func newProxyController(t *testing.T) (*controllertest.TestRunner, *ProxyController) {
	runner := controllertest.NewTestRunner()
	controller, err := NewProxyController(
		runner.SharedInformerFactory,
		runner.CoreSharedInformerFactory,
		runner.CoreClient,
		runner.Client,
	)
	require.NoError(t, err)

	return runner, controller
}

func registerFixtureFromProcess(runner *controllertest.TestRunner, p *process) {
	for _, v := range p.Service {
		runner.RegisterFixtures(v)
	}

	for _, v := range p.ConfigMaps {
		runner.RegisterFixtures(v)
	}

	runner.RegisterFixtures(p.Deployment, p.PodDisruptionBudget)
}

func registerFixtures(
	runner *controllertest.TestRunner,
	secret *corev1.Secret,
	backends []*proxyv1alpha2.Backend,
	roles []*proxyv1alpha2.Role,
	rpcPermissions []*proxyv1alpha2.RpcPermission,
	roleBindings []*proxyv1alpha2.RoleBinding,
	services []*corev1.Service,
) {
	runner.RegisterFixtures(secret)
	for _, v := range backends {
		runner.RegisterFixtures(v)
	}
	for _, v := range roles {
		runner.RegisterFixtures(v)
	}
	for _, v := range rpcPermissions {
		runner.RegisterFixtures(v)
	}
	for _, v := range roleBindings {
		runner.RegisterFixtures(v)
	}
	for _, v := range services {
		runner.RegisterFixtures(v)
	}
}

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

func setProxyStatus(object interface{}) {
	p, ok := object.(*proxyv1alpha2.Proxy)
	if !ok {
		return
	}

	p.Status.CASecretName = fmt.Sprintf("%s-ca", p.Name)
	p.Status.SigningPrivateKeySecretName = fmt.Sprintf("%s-privkey", p.Name)
	p.Status.GithubWebhookSecretName = fmt.Sprintf("%s-github-secret", p.Name)
	p.Status.CookieSecretName = fmt.Sprintf("%s-cookie-secret", p.Name)
	p.Status.InternalTokenSecretName = fmt.Sprintf("%s-internal-token", p.Name)
}

func setProxyStatusNumberOf(object interface{}) {
	p, ok := object.(*proxyv1alpha2.Proxy)
	if !ok {
		return
	}

	p.Status.NumOfBackends = 2
	p.Status.NumOfRoles = 2
	p.Status.NumOfRpcPermissions = 1
}

func newHeimdallrProxy(
	client *fake.Clientset,
	serviceLister listers.ServiceLister,
	p *proxyv1alpha2.Proxy,
	backends []*proxyv1alpha2.Backend,
	roles []*proxyv1alpha2.Role,
	roleBindings []*proxyv1alpha2.RoleBinding,
	rpcPermissions []*proxyv1alpha2.RpcPermission,
) *HeimdallrProxy {
	hp := NewHeimdallrProxy(HeimdallrProxyParams{
		Spec:           p,
		Clientset:      client,
		ServiceLister:  serviceLister,
		Backends:       backends,
		Roles:          roles,
		RpcPermissions: rpcPermissions,
		RoleBindings:   roleBindings,
	})
	hp.backends = append(hp.backends, hp.DefaultBackends()...)
	hp.roles = append(hp.roles, hp.DefaultRoles()...)
	hp.roleBindings = append(hp.roleBindings, hp.DefaultRoleBindings()...)
	hp.rpcPermissions = append(hp.rpcPermissions, hp.DefaultRpcPermissions()...)
	return hp
}
