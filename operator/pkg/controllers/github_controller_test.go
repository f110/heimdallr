package controllers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"regexp"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	proxyv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha1"
)

func TestGitHubController(t *testing.T) {
	t.Run("CreateHook", func(t *testing.T) {
		t.Parallel()

		f := newGitHubControllerTestRunner(t)

		f.transport.RegisterResponder(
			http.MethodPost,
			"https://api.github.com/app/installations/2/access_tokens",
			httpmock.NewStringResponder(http.StatusOK, `{"token":"mocktoken"}`),
		)
		f.transport.RegisterResponder(
			http.MethodGet,
			"https://api.github.com/repos/f110/heimdallr/hooks",
			httpmock.NewStringResponder(http.StatusOK, `[]`),
		)
		f.transport.RegisterResponder(
			http.MethodPost,
			"https://api.github.com/repos/f110/heimdallr/hooks",
			httpmock.NewStringResponder(http.StatusOK, `{}`),
		)

		proxy, backend, secrets := githubControllerFixtures(t, "test")
		f.RegisterProxyFixture(proxy)
		f.RegisterBackendFixture(backend)
		f.RegisterSecretFixture(secrets...)

		f.ExpectUpdateBackend()
		f.ExpectUpdateBackendStatus()
		f.Run(t, backend)

		ExpectCall(t, f.transport.GetCallCountInfo(), http.MethodPost, "https://api.github.com/repos/f110/heimdallr/hooks")

		updatedB, err := f.client.ProxyV1alpha1().Backends(backend.Namespace).Get(context.TODO(), backend.Name, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Contains(t, updatedB.Finalizers, githubControllerFinalizerName)
	})

	t.Run("DeleteHook", func(t *testing.T) {
		t.Parallel()

		f := newGitHubControllerTestRunner(t)

		proxy, backend, secrets := githubControllerFixtures(t, "test")
		now := metav1.Now()
		backend.DeletionTimestamp = &now
		backend.Finalizers = append(backend.Finalizers, githubControllerFinalizerName)
		backend.Status.WebhookConfigurations = append(backend.Status.WebhookConfigurations, &proxyv1alpha1.WebhookConfigurationStatus{
			Id:         1234,
			Repository: "f110/heimdallr",
			UpdateTime: metav1.Now(),
		})
		f.RegisterProxyFixture(proxy)
		f.RegisterBackendFixture(backend)
		f.RegisterSecretFixture(secrets...)

		f.transport.RegisterResponder(
			http.MethodPost,
			"https://api.github.com/app/installations/2/access_tokens",
			httpmock.NewStringResponder(http.StatusOK, `{"token":"mocktoken"}`),
		)
		f.transport.RegisterRegexpResponder(
			http.MethodDelete,
			regexp.MustCompile(`/repos/f110/heimdallr/hooks/1234$`),
			httpmock.NewStringResponder(http.StatusNoContent, ""),
		)

		f.ExpectUpdateBackend()
		f.Run(t, backend)
	})
}

func ExpectCall(t *testing.T, callInfo map[string]int, method, url string) {
	if _, ok := callInfo[fmt.Sprintf("%s %s", method, url)]; !ok {
		t.Errorf("Expect call %s %s", method, url)
	}
}

func githubControllerFixtures(t *testing.T, name string) (proxy *proxyv1alpha1.Proxy, backend *proxyv1alpha1.Backend, secret []*corev1.Secret) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)
	err = pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err != nil {
		t.Fatal(err)
	}

	p := &proxyv1alpha1.Proxy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: proxyv1alpha1.ProxySpec{
			Domain: "test-proxy.f110.dev",
		},
		Status: proxyv1alpha1.ProxyStatus{
			GithubWebhookSecretName: "github-webhook-secret",
		},
	}

	b := &proxyv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: metav1.NamespaceDefault,
		},
		Spec: proxyv1alpha1.BackendSpec{
			Layer:   "test",
			Webhook: "github",
			WebhookConfiguration: &proxyv1alpha1.WebhookConfiguration{
				GitHubHookConfiguration: proxyv1alpha1.GitHubHookConfiguration{
					Path:                 "/hook",
					ContentType:          "application/json",
					Events:               []string{"push"},
					CredentialSecretName: "github-secret",
					Repositories:         []string{"f110/heimdallr"},
					AppIdKey:             "appid",
					InstallationIdKey:    "installationid",
					PrivateKeyKey:        "privatekey",
				},
			},
		},
		Status: proxyv1alpha1.BackendStatus{
			DeployedBy: []*proxyv1alpha1.ProxyReference{
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
