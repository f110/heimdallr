package controllers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	etcdv1alpha1 "github.com/f110/lagrangian-proxy/operator/pkg/api/etcd/v1alpha1"
	proxyv1 "github.com/f110/lagrangian-proxy/operator/pkg/api/proxy/v1"
	"github.com/f110/lagrangian-proxy/pkg/config"
)

func newProxy(name string) (*proxyv1.Proxy, *corev1.Secret, []proxyv1.Backend, []proxyv1.Role, []proxyv1.RpcPermission) {
	proxy := &proxyv1.Proxy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceDefault,
		},
		Spec: proxyv1.ProxySpec{
			BackendSelector: proxyv1.LabelSelector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"instance": "test"},
				},
			},
			RoleSelector: proxyv1.LabelSelector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"instance": "test"},
				},
			},
			RpcPermissionSelector: proxyv1.LabelSelector{
				LabelSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{"instance": "test"},
				},
			},
			Session: proxyv1.SessionSpec{
				Type: config.SessionTypeSecureCookie,
			},
			IdentityProvider: proxyv1.IdentityProviderSpec{
				Provider: "google",
				ClientSecretRef: proxyv1.SecretSelector{
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

	backends := []proxyv1.Backend{}

	roles := []proxyv1.Role{}

	rpcPermissions := []proxyv1.RpcPermission{}

	return proxy, clientSecret, backends, roles, rpcPermissions
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
		for _, v := range p.ConfigMaps {
			f.RegisterConfigMapFixture(v)
		}
	}
}

func TestProxyController(t *testing.T) {
	t.Run("New", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)

		p, clientSecret, backends, roles, rpcPermissions := newProxy("test")
		f.RegisterProxyFixture(p)
		f.RegisterSecretFixture(clientSecret)

		proxy := NewLagrangianProxy(p, f.cmClient, f.c.serviceLister, backends, roles, rpcPermissions)

		for _, v := range proxy.Secrets() {
			_, err := v.Create()
			if err != nil {
				t.Fatal(err)
			}
			f.ExpectCreateSecret()
		}
		f.ExpectCreateEtcdCluster()

		f.RunExpectError(t, p, ErrEtcdClusterIsNotReady)
	})

	t.Run("Preparing phase when EtcdCluster is not ready", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)

		p, clientSecret, backends, roles, rpcPermissions := newProxy("test")
		f.RegisterProxyFixture(p)
		f.RegisterSecretFixture(clientSecret)

		proxy := NewLagrangianProxy(p, f.cmClient, f.c.serviceLister, backends, roles, rpcPermissions)
		ec, _ := proxy.EtcdCluster()
		f.RegisterEtcdClusterFixture(ec)
		for _, v := range proxy.Secrets() {
			s, err := v.Create()
			if err != nil {
				t.Fatal(err)
			}
			f.RegisterSecretFixture(s)
		}

		f.RunExpectError(t, p, ErrEtcdClusterIsNotReady)
	})

	t.Run("Finish preparing phase", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)

		p, clientSecret, backends, roles, rpcPermissions := newProxy("test")
		f.RegisterProxyFixture(p)
		f.RegisterSecretFixture(clientSecret)

		proxy := NewLagrangianProxy(p, f.cmClient, f.c.serviceLister, backends, roles, rpcPermissions)
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
		f.ExpectCreateService()
		f.ExpectCreateConfigMap()
		f.ExpectCreateConfigMap()
		f.RunExpectError(t, p, ErrRPCServerIsNotReady)

		updatedP, err := f.client.ProxyV1().Proxies(p.Namespace).Get(p.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		assert.NotEmpty(t, updatedP.Status.CASecretName)
		assert.NotEmpty(t, updatedP.Status.SigningPrivateKeySecretName)
		assert.NotEmpty(t, updatedP.Status.GithubWebhookSecretName)
		assert.NotEmpty(t, updatedP.Status.InternalTokenSecretName)
		assert.NotEmpty(t, updatedP.Status.CookieSecretName)
	})

	t.Run("RPC server is ready", func(t *testing.T) {
		t.Parallel()

		f := newFixture(t)

		p, clientSecret, backends, roles, rpcPermissions := newProxy("test")
		f.RegisterProxyFixture(p)
		f.RegisterSecretFixture(clientSecret)

		proxy := NewLagrangianProxy(p, f.cmClient, f.c.serviceLister, backends, roles, rpcPermissions)
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
		// Expect to create the dashboard
		f.ExpectCreateDeployment()
		f.ExpectCreatePodDisruptionBudget()
		f.ExpectCreateService()
		f.ExpectCreateConfigMap()
		// Finally update the status of proxy
		f.ExpectUpdateProxyStatus()
		f.Run(t, p)

		updatedP, err := f.client.ProxyV1().Proxies(p.Namespace).Get(p.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		assert.False(t, updatedP.Status.Ready)
		assert.Equal(t, updatedP.Status.Phase, proxyv1.ProxyPhaseRunning)
	})
}
