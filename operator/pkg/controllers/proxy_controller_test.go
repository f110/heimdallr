package controllers

import (
	"testing"

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

	backends := []proxyv1.Backend{{}}

	roles := []proxyv1.Role{{}}

	rpcPermissions := []proxyv1.RpcPermission{{}}

	return proxy, clientSecret, backends, roles, rpcPermissions
}

func newEtcdCluster(name string) *etcdv1alpha1.EtcdCluster {
	return &etcdv1alpha1.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name + "-datastore",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: etcdv1alpha1.EtcdClusterSpec{
			Members: 3,
			Version: EtcdVersion,
		},
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
			s, err := v.Create()
			if err != nil {
				t.Fatal(err)
			}
			f.ExpectCreateSecretAction(s)
		}
		f.ExpectCreateEtcdClusterAction(newEtcdCluster("test"))

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
}
