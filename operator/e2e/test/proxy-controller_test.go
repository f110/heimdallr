package test

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"testing"
	"time"

	certmanagermetav1 "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	. "github.com/smartystreets/goconvey/convey"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"go.f110.dev/heimdallr/operator/e2e/e2eutil"
	. "go.f110.dev/heimdallr/operator/e2e/framework"
	proxyv1 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
	"go.f110.dev/heimdallr/pkg/config"
)

func TestProxyController(t *testing.T) {
	t.Parallel()

	Describe(t, "ProxyController", func() {
		It("serves http request", func() {
			testUserId := "e2e@f110.dev"
			client, err := clientset.NewForConfig(RESTConfig)
			if err != nil {
				t.Fatal(err)
			}
			coreClient, err := kubernetes.NewForConfig(RESTConfig)
			if err != nil {
				t.Fatal(err)
			}

			clientSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "e2e-client-secret",
					Namespace: "default",
				},
				Data: map[string][]byte{
					"client-secret": []byte("client-secret"),
				},
			}
			_, err = coreClient.CoreV1().Secrets(clientSecret.Namespace).Create(clientSecret)
			if err != nil {
				t.Fatal(err)
			}

			proxy := &proxyv1.Proxy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "create",
					Namespace: "default",
				},
				Spec: proxyv1.ProxySpec{
					Version:     Config.ProxyVersion,
					EtcdVersion: "v3.4.8",
					Domain:      "e2e.f110.dev",
					Replicas:    3,
					BackendSelector: proxyv1.LabelSelector{
						LabelSelector: metav1.LabelSelector{},
					},
					IdentityProvider: proxyv1.IdentityProviderSpec{
						Provider: "google",
						ClientId: "e2e",
						ClientSecretRef: proxyv1.SecretSelector{
							Name: clientSecret.Name,
							Key:  "client-secret",
						},
					},
					IssuerRef: certmanagermetav1.ObjectReference{
						Kind: "ClusterIssuer",
						Name: "self-signed",
					},
					Session: proxyv1.SessionSpec{
						Type: config.SessionTypeSecureCookie,
					},
					RootUsers: []string{testUserId},
				},
			}

			testServiceBackend, err := e2eutil.DeployTestService(coreClient, client, proxy, "hello")
			if err != nil {
				t.Fatal(err)
			}
			disableAuthnTestBackend, err := e2eutil.DeployDisableAuthnTestService(coreClient, client, proxy, "disauth")
			if err != nil {
				t.Fatal(err)
			}
			role := &proxyv1.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "admin",
					Namespace: proxy.Namespace,
					Labels:    proxy.Spec.RoleSelector.MatchLabels,
				},
				Spec: proxyv1.RoleSpec{
					Title:       "administrator",
					Description: "admin",
				},
			}
			role, err = client.ProxyV1().Roles(role.Namespace).Create(role)
			if err != nil {
				t.Fatal(err)
			}
			roleBinding := &proxyv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "admin",
					Namespace: proxy.Namespace,
				},
				RoleRef: proxyv1.RoleRef{
					Name:      "admin",
					Namespace: proxy.Namespace,
				},
				Subjects: []proxyv1.Subject{
					{Kind: "Backend", Name: "dashboard", Namespace: proxy.Namespace, Permission: "all"},
					{Kind: "Backend", Name: testServiceBackend.Name, Namespace: proxy.Namespace, Permission: "all"},
					{Kind: "Backend", Name: disableAuthnTestBackend.Name, Namespace: proxy.Namespace, Permission: "all"},
				},
			}
			_, err = client.ProxyV1().RoleBindings(proxy.Namespace).Create(roleBinding)
			if err != nil {
				t.Fatal(err)
			}

			_, err = client.ProxyV1().Proxies(proxy.Namespace).Create(proxy)
			if err != nil {
				t.Fatal(err)
			}

			if err := e2eutil.WaitForStatusOfProxyBecome(client, proxy, proxyv1.ProxyPhaseRunning, 15*time.Minute); err != nil {
				t.Fatal(err)
			}
			if err := e2eutil.WaitForReadyOfProxy(client, proxy, 10*time.Minute); err != nil {
				t.Fatal(err)
			}

			proxy, err = client.ProxyV1().Proxies(proxy.Namespace).Get(proxy.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}

			rpcClient, err := e2eutil.DialRPCServer(RESTConfig, coreClient, proxy, testUserId)
			if err != nil {
				t.Fatal(err)
			}
			if err := e2eutil.EnsureExistingTestUser(rpcClient, testUserId, role.Name); err != nil {
				t.Fatal(err)
			}
			clientCert, err := e2eutil.SetupClientCert(rpcClient, testUserId)
			if err != nil {
				t.Fatal(err)
			}
			proxyCertPool, err := e2eutil.ProxyCertPool(coreClient, proxy)
			if err != nil {
				t.Fatal(err)
			}

			proxyService, err := coreClient.CoreV1().Services(proxy.Namespace).Get(fmt.Sprintf("%s", proxy.Name), metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			forwarder, err := e2eutil.PortForward(context.Background(), RESTConfig, coreClient, proxyService, "https")
			if err != nil {
				t.Fatal(err)
			}
			ports, err := forwarder.GetPorts()
			if err != nil {
				t.Fatal(err)
			}
			port := ports[0].Local

			testReq, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d", port), nil)
			if err != nil {
				t.Fatal(err)
			}
			testReq.Host = fmt.Sprintf("%s.%s.%s", testServiceBackend.Name, testServiceBackend.Spec.Layer, proxy.Spec.Domain)
			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
				RootCAs:      proxyCertPool,
				ServerName:   testReq.Host,
				Certificates: []tls.Certificate{*clientCert},
			}
			res, err := http.DefaultClient.Do(testReq)
			if err != nil {
				b, _ := httputil.DumpRequest(testReq, true)
				log.Print(string(b))
				t.Fatal(err)
			}

			So(res.StatusCode, ShouldEqual, http.StatusOK)
			So(res.Header.Get("Server"), ShouldContainSubstring, "nginx")

			testReq, err = http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d", port), nil)
			if err != nil {
				t.Fatal(err)
			}
			testReq.Host = fmt.Sprintf("%s.%s.%s", testServiceBackend.Name, testServiceBackend.Spec.Layer, proxy.Spec.Domain)
			http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
				RootCAs:    proxyCertPool,
				ServerName: testReq.Host,
			}
			res, err = http.DefaultClient.Do(testReq)
			if err != nil {
				b, _ := httputil.DumpRequest(testReq, true)
				log.Print(string(b))
				t.Fatal(err)
			}
		})
	})
}
