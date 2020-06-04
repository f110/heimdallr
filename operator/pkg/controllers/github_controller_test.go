package controllers

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	proxyv1 "github.com/f110/lagrangian-proxy/operator/pkg/api/proxy/v1"
)

func TestGitHubController(t *testing.T) {
	f := newGitHubControllerTestRunner(t)

	f.transport.RegisterResponder(
		http.MethodPost,
		"https://api.github.com/app/installations/2/access_tokens",
		httpmock.NewStringResponder(http.StatusOK, `{"token":"mocktoken"}`),
	)
	f.transport.RegisterResponder(
		http.MethodGet,
		"https://api.github.com/repos/f110/lagrangian-proxy/hooks",
		httpmock.NewStringResponder(http.StatusOK, `[]`),
	)
	f.transport.RegisterResponder(
		http.MethodPost,
		"https://api.github.com/repos/f110/lagrangian-proxy/hooks",
		httpmock.NewStringResponder(http.StatusOK, `{}`),
	)

	proxy, backend, secrets := githubControllerFixtures(t, "test")
	f.RegisterProxyFixture(proxy)
	f.RegisterBackendFixture(backend)
	f.RegisterSecretFixture(secrets...)

	f.ExpectUpdateBackendStatus()
	f.Run(t, backend)

	ExpectCall(t, f.transport.GetCallCountInfo(), http.MethodPost, "https://api.github.com/repos/f110/lagrangian-proxy/hooks")
}

func ExpectCall(t *testing.T, callInfo map[string]int, method, url string) {
	if _, ok := callInfo[fmt.Sprintf("%s %s", method, url)]; !ok {
		t.Errorf("Expect call %s %s", method, url)
	}
}

func githubControllerFixtures(t *testing.T, name string) (proxy *proxyv1.Proxy, backend *proxyv1.Backend, secret []*corev1.Secret) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	err = pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err != nil {
		t.Fatal(err)
	}

	p := &proxyv1.Proxy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: proxyv1.ProxySpec{
			Domain: "test-proxy.f110.dev",
		},
		Status: proxyv1.ProxyStatus{
			GithubWebhookSecretName: "github-webhook-secret",
		},
	}

	b := &proxyv1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceDefault,
		},
		Spec: proxyv1.BackendSpec{
			Layer:   "test",
			Webhook: "github",
			WebhookConfiguration: &proxyv1.WebhookConfiguration{
				GitHubHookConfiguration: proxyv1.GitHubHookConfiguration{
					Path:                 "/hook",
					ContentType:          "application/json",
					Events:               []string{"push"},
					CredentialSecretName: "github-secret",
					Repositories:         []string{"f110/lagrangian-proxy"},
					AppIdKey:             "appid",
					InstallationIdKey:    "installationid",
					PrivateKeyKey:        "privatekey",
				},
			},
		},
		Status: proxyv1.BackendStatus{
			DeployedBy: []*proxyv1.ProxyReference{
				{Name: p.Name, Namespace: metav1.NamespaceDefault, Url: fmt.Sprintf("https://test.test.%s", p.Spec.Domain)},
			},
		},
	}

	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "github-secret",
			Namespace: metav1.NamespaceDefault,
		},
		Data: map[string][]byte{
			"appid":          []byte("1"),
			"installationid": []byte("2"),
			"privatekey":     buf.Bytes(),
		},
	}
	webhookSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "github-webhook-secret",
			Namespace: metav1.NamespaceDefault,
		},
		Data: map[string][]byte{githubWebhookSecretFilename: []byte("test")},
	}

	return p, b, []*corev1.Secret{s, webhookSecret}
}
