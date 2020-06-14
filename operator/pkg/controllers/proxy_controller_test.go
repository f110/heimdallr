package controllers

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	etcdv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha1"
	proxyv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha1"
	"go.f110.dev/heimdallr/pkg/config"
)

func newProxy(name string) (*proxyv1alpha1.Proxy, *corev1.Secret, []*proxyv1alpha1.Backend, []*proxyv1alpha1.Role, []proxyv1alpha1.RpcPermission, []*proxyv1alpha1.RoleBinding, []corev1.Service) {
	proxy := &proxyv1alpha1.Proxy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceDefault,
		},
		Spec: proxyv1alpha1.ProxySpec{
			Domain:      "test-proxy.f110.dev",
			EtcdVersion: "v3.4.9",
			BackendSelector: proxyv1alpha1.LabelSelector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"instance": "test"},
				},
			},
			RoleSelector: proxyv1alpha1.LabelSelector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"instance": "test"},
				},
			},
			RpcPermissionSelector: proxyv1alpha1.LabelSelector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"instance": "test"},
				},
			},
			Session: proxyv1alpha1.SessionSpec{
				Type: config.SessionTypeSecureCookie,
			},
			IdentityProvider: proxyv1alpha1.IdentityProviderSpec{
				Provider: "google",
				ClientSecretRef: proxyv1alpha1.SecretSelector{
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

	backends := []*proxyv1alpha1.Backend{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "test",
				Namespace:         metav1.NamespaceDefault,
				CreationTimestamp: metav1.Now(),
				Labels:            map[string]string{"instance": "test"},
			},
			Spec: proxyv1alpha1.BackendSpec{
				Layer: "test",
				ServiceSelector: proxyv1alpha1.ServiceSelector{
					LabelSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "test"},
					},
				},
				Permissions: []proxyv1alpha1.Permission{
					{Name: "all", Locations: []proxyv1alpha1.Location{{Any: "/"}}},
				},
			},
		},
	}

	roles := []*proxyv1alpha1.Role{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "test",
				Namespace:         metav1.NamespaceDefault,
				CreationTimestamp: metav1.Now(),
				Labels:            map[string]string{"instance": "test"},
			},
			Spec: proxyv1alpha1.RoleSpec{
				Title:       "test",
				Description: "for testing",
			},
		},
	}
	rpcPermissions := []proxyv1alpha1.RpcPermission{}
	roleBindings := []*proxyv1alpha1.RoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "test-test",
				Namespace:         metav1.NamespaceDefault,
				CreationTimestamp: metav1.Now(),
			},
			Subjects: []proxyv1alpha1.Subject{
				{Kind: "Backend", Name: "test", Namespace: metav1.NamespaceDefault, Permission: "all"},
			},
			RoleRef: proxyv1alpha1.RoleRef{
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
			Spec:              p,
			CertManagerClient: f.cmClient,
			ServiceLister:     f.c.serviceLister,
			Backends:          backends,
			Roles:             roles,
			RpcPermissions:    rpcPermissions,
			RoleBindings:      roleBindings,
		})

		for _, v := range proxy.Secrets() {
			_, err := v.Create()
			if err != nil {
				t.Fatal(err)
			}
			f.ExpectCreateSecret()
		}
		f.ExpectUpdateProxyStatus()
		f.ExpectCreateEtcdCluster()

		f.RunExpectError(t, p, ErrEtcdClusterIsNotReady)
	})

	t.Run("Preparing phase when EtcdCluster is not ready", func(t *testing.T) {
		t.Parallel()

		f := newProxyControllerTestRunner(t)

		p, clientSecret, backends, roles, rpcPermissions, roleBindings, _ := newProxy("test")
		f.RegisterProxyFixture(p)
		f.RegisterSecretFixture(clientSecret)

		proxy := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec:              p,
			CertManagerClient: f.cmClient,
			ServiceLister:     f.c.serviceLister,
			Backends:          backends,
			Roles:             roles,
			RpcPermissions:    rpcPermissions,
			RoleBindings:      roleBindings,
		})
		ec, _ := proxy.EtcdCluster()
		f.RegisterEtcdClusterFixture(ec)
		for _, v := range proxy.Secrets() {
			s, err := v.Create()
			if err != nil {
				t.Fatal(err)
			}
			f.RegisterSecretFixture(s)
		}

		f.ExpectUpdateProxyStatus()
		f.RunExpectError(t, p, ErrEtcdClusterIsNotReady)

		etcdC, err := f.client.EtcdV1alpha1().EtcdClusters(ec.Namespace).Get(ec.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, p.Spec.EtcdVersion, etcdC.Spec.Version)
	})

	t.Run("Finish preparing phase", func(t *testing.T) {
		t.Parallel()

		f := newProxyControllerTestRunner(t)

		p, clientSecret, backends, roles, rpcPermissions, roleBindings, _ := newProxy("test")
		f.RegisterProxyFixture(p)
		f.RegisterBackendFixture(backends...)
		f.RegisterRoleFixture(roles...)
		f.RegisterRoleBindingFixture(roleBindings...)
		f.RegisterSecretFixture(clientSecret)

		proxy := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec:              p,
			CertManagerClient: f.cmClient,
			ServiceLister:     f.c.serviceLister,
			Backends:          backends,
			Roles:             roles,
			RpcPermissions:    rpcPermissions,
			RoleBindings:      roleBindings,
		})
		ec, _ := proxy.EtcdCluster()
		ec.Status.Ready = true
		ec.Status.Phase = etcdv1alpha1.ClusterPhaseRunning
		f.RegisterEtcdClusterFixture(ec)
		for _, v := range proxy.Secrets() {
			s, err := v.Create()
			if err != nil {
				t.Fatal(err)
			}
			f.RegisterSecretFixture(s)
		}
		f.client.Tracker().Add(p)

		f.ExpectUpdateProxyStatus()
		f.ExpectCreateDeployment()
		f.ExpectCreatePodDisruptionBudget()
		f.ExpectCreateService()
		f.ExpectCreateConfigMap()
		f.ExpectCreateConfigMap()
		f.ExpectUpdateProxyStatus()
		f.RunExpectError(t, p, ErrRPCServerIsNotReady)

		updatedP, err := f.client.ProxyV1alpha1().Proxies(p.Namespace).Get(p.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		proxyConfigMap, err := f.coreClient.CoreV1().ConfigMaps(proxy.Namespace).Get(proxy.ReverseProxyConfigName(), metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}

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
		f.RegisterRoleFixture(roles...)
		f.RegisterRoleBindingFixture(roleBindings...)
		for _, s := range services {
			f.RegisterServiceFixture(&s)
		}
		f.RegisterSecretFixture(clientSecret)

		proxy := NewHeimdallrProxy(HeimdallrProxyParams{
			Spec:              p,
			CertManagerClient: f.cmClient,
			ServiceLister:     f.c.serviceLister,
			Backends:          backends,
			Roles:             roles,
			RpcPermissions:    rpcPermissions,
			RoleBindings:      roleBindings,
		})
		ec, _ := proxy.EtcdCluster()
		ec.Status.Ready = true
		ec.Status.Phase = etcdv1alpha1.ClusterPhaseRunning
		proxy.Datastore = ec
		f.RegisterEtcdClusterFixture(ec)
		for _, v := range proxy.Secrets() {
			s, err := v.Create()
			if err != nil {
				t.Fatal(err)
			}
			f.RegisterSecretFixture(s)
		}
		f.client.Tracker().Add(p)
		pcs, err := proxy.IdealRPCServer()
		if err != nil {
			t.Fatal(err)
		}
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

		updatedP, err := f.client.ProxyV1alpha1().Proxies(p.Namespace).Get(p.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		assert.False(t, updatedP.Status.Ready)
		assert.Equal(t, updatedP.Status.Phase, proxyv1alpha1.ProxyPhaseRunning)

		for _, backend := range backends {
			updatedB, err := f.client.ProxyV1alpha1().Backends(backend.Namespace).Get(backend.Name, metav1.GetOptions{})
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
