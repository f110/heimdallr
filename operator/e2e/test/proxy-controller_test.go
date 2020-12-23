package test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"testing"
	"time"

	certmanagermetav1 "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/smartystreets/goconvey/convey"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"go.f110.dev/heimdallr/operator/e2e/e2eutil"
	"go.f110.dev/heimdallr/operator/e2e/framework"
	proxyv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha2"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
	"go.f110.dev/heimdallr/pkg/config"
)

func TestProxyController(t *testing.T) {
	t.Parallel()

	framework.Describe(t, "ProxyController", func() {
		framework.It("serves http request", func() {
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
			_, err = coreClient.CoreV1().Secrets(clientSecret.Namespace).Create(context.TODO(), clientSecret, metav1.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}

			proxy := &proxyv1alpha2.Proxy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "create",
					Namespace: "default",
				},
				Spec: proxyv1alpha2.ProxySpec{
					Development: true,
					Version:     framework.Config.ProxyVersion,
					DataStore: &proxyv1alpha2.ProxyDataStoreSpec{
						Etcd: &proxyv1alpha2.ProxyDataStoreEtcdSpec{
							Version:      "v3.4.8",
							AntiAffinity: true,
						},
					},
					Domain:   "e2e.f110.dev",
					Replicas: 3,
					CertificateAuthority: &proxyv1alpha2.CertificateAuthoritySpec{
						Local: &proxyv1alpha2.LocalCertificateAuthoritySpec{
							Name: "e2e",
						},
					},
					BackendSelector: proxyv1alpha2.LabelSelector{
						LabelSelector: metav1.LabelSelector{},
					},
					IdentityProvider: proxyv1alpha2.IdentityProviderSpec{
						Provider: "google",
						ClientId: "e2e",
						ClientSecretRef: proxyv1alpha2.SecretSelector{
							Name: clientSecret.Name,
							Key:  "client-secret",
						},
					},
					IssuerRef: certmanagermetav1.ObjectReference{
						Kind: "ClusterIssuer",
						Name: "self-signed",
					},
					Session: proxyv1alpha2.SessionSpec{
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
			role := &proxyv1alpha2.Role{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "admin",
					Namespace: proxy.Namespace,
					Labels:    proxy.Spec.RoleSelector.MatchLabels,
				},
				Spec: proxyv1alpha2.RoleSpec{
					Title:       "administrator",
					Description: "admin",
				},
			}
			role, err = client.ProxyV1alpha2().Roles(role.Namespace).Create(context.TODO(), role, metav1.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}
			roleBinding := &proxyv1alpha2.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "admin",
					Namespace: proxy.Namespace,
				},
				RoleRef: proxyv1alpha2.RoleRef{
					Name:      "admin",
					Namespace: proxy.Namespace,
				},
				Subjects: []proxyv1alpha2.Subject{
					{Kind: "Backend", Name: "dashboard", Namespace: proxy.Namespace, Permission: "all"},
					{Kind: "Backend", Name: testServiceBackend.Name, Namespace: proxy.Namespace, Permission: "all"},
					{Kind: "Backend", Name: disableAuthnTestBackend.Name, Namespace: proxy.Namespace, Permission: "all"},
				},
			}
			_, err = client.ProxyV1alpha2().RoleBindings(proxy.Namespace).Create(context.TODO(), roleBinding, metav1.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}

			_, err = client.ProxyV1alpha2().Proxies(proxy.Namespace).Create(context.TODO(), proxy, metav1.CreateOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if err := e2eutil.WaitForStatusOfProxyBecome(client, proxy, proxyv1alpha2.ProxyPhaseRunning, 15*time.Minute); err != nil {
				t.Fatal(err)
			}
			if err := e2eutil.WaitForReadyOfProxy(client, proxy, 10*time.Minute); err != nil {
				t.Fatal(err)
			}

			proxy, err = client.ProxyV1alpha2().Proxies(proxy.Namespace).Get(context.TODO(), proxy.Name, metav1.GetOptions{})
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

			proxyService, err := coreClient.CoreV1().Services(proxy.Namespace).Get(context.TODO(), fmt.Sprintf("%s", proxy.Name), metav1.GetOptions{})
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

			// Request testService which is nginx with client credential
			testReq := newRequest(
				t,
				http.MethodGet,
				fmt.Sprintf("https://127.0.0.1:%d", port),
				fmt.Sprintf("%s.%s.%s", testServiceBackend.Name, testServiceBackend.Spec.Layer, proxy.Spec.Domain),
				nil,
			)
			res := doRequest(t, testReq, proxyCertPool, clientCert)
			convey.So(res.StatusCode, convey.ShouldEqual, http.StatusOK)
			convey.So(res.Header.Get("Server"), convey.ShouldContainSubstring, "nginx")

			// Request testService which is nginx without client credential
			testReq = newRequest(
				t,
				http.MethodGet,
				fmt.Sprintf("https://127.0.0.1:%d", port),
				fmt.Sprintf("%s.%s.%s", testServiceBackend.Name, testServiceBackend.Spec.Layer, proxy.Spec.Domain),
				nil,
			)
			res = doRequest(t, testReq, proxyCertPool, nil)
			convey.So(res.StatusCode, convey.ShouldEqual, http.StatusSeeOther)

			// Request dashboard
			testReq = newRequest(
				t,
				http.MethodGet,
				fmt.Sprintf("https://127.0.0.1:%d", port),
				fmt.Sprintf("%s.%s", "dashboard", proxy.Spec.Domain),
				nil,
			)
			res = doRequest(t, testReq, proxyCertPool, clientCert)
			convey.So(res.StatusCode, convey.ShouldEqual, http.StatusOK)
		})
	})
}

func newRequest(t *testing.T, method, url, host string, body io.Reader) *http.Request {
	testReq, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	testReq.Host = host

	return testReq
}

func doRequest(t *testing.T, req *http.Request, ca *x509.CertPool, clientCert *tls.Certificate) *http.Response {
	tlsConfig := &tls.Config{
		RootCAs:    ca,
		ServerName: req.Host,
	}
	if clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCert}
	}
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}
	client := &http.Client{
		Transport: transport,
		// Do not follow redirect
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	res, err := client.Do(req)
	if err != nil {
		b, _ := httputil.DumpRequest(req, true)
		log.Print(string(b))
		t.Fatal(err)
	}

	return res
}
