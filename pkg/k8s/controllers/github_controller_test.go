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
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.f110.dev/heimdallr/pkg/k8s/api/proxy"
	proxyv1alpha2 "go.f110.dev/heimdallr/pkg/k8s/api/proxy/v1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/controllers/controllertest"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
)

func TestGitHubController(t *testing.T) {
	t.Run("CreateHook", func(t *testing.T) {
		t.Parallel()

		runner := controllertest.NewTestRunner()
		transport := httpmock.NewMockTransport()
		controller, err := NewGitHubController(
			runner.SharedInformerFactory,
			runner.CoreSharedInformerFactory,
			runner.CoreClient,
			runner.Client,
			transport,
		)
		require.NoError(t, err)

		transport.RegisterResponder(
			http.MethodPost,
			"https://api.github.com/app/installations/2/access_tokens",
			httpmock.NewStringResponder(http.StatusOK, `{"token":"mocktoken"}`),
		)
		transport.RegisterResponder(
			http.MethodGet,
			"https://api.github.com/repos/f110/heimdallr/hooks",
			httpmock.NewStringResponder(http.StatusOK, `[]`),
		)
		transport.RegisterResponder(
			http.MethodPost,
			"https://api.github.com/repos/f110/heimdallr/hooks",
			httpmock.NewStringResponder(http.StatusOK, `{}`),
		)

		p, backend, secrets := githubControllerFixtures(t, "test")
		runner.RegisterFixtures(p)
		for _, v := range secrets {
			runner.RegisterFixtures(v)
		}

		err = runner.Reconcile(controller, backend)
		require.NoError(t, err)

		updated, err := runner.Client.ProxyV1alpha2().Backends(backend.Namespace).Get(context.TODO(), backend.Name, metav1.GetOptions{})
		require.NoError(t, err)
		runner.AssertUpdateAction(t, "status", updated)
		runner.AssertNoUnexpectedAction(t)

		ExpectCall(t, transport.GetCallCountInfo(), http.MethodPost, "https://api.github.com/repos/f110/heimdallr/hooks")
	})

	t.Run("DeleteHook", func(t *testing.T) {
		t.Parallel()

		runner := controllertest.NewTestRunner()
		transport := httpmock.NewMockTransport()
		controller, err := NewGitHubController(
			runner.SharedInformerFactory,
			runner.CoreSharedInformerFactory,
			runner.CoreClient,
			runner.Client,
			transport,
		)
		require.NoError(t, err)

		p, backend, secrets := githubControllerFixtures(t, "test")
		backend = proxy.BackendFactory(backend, k8sfactory.Delete, k8sfactory.Finalizer(githubControllerFinalizerName))
		backend.Status.WebhookConfigurations = append(backend.Status.WebhookConfigurations, &proxyv1alpha2.WebhookConfigurationStatus{
			Id:         1234,
			Repository: "f110/heimdallr",
			UpdateTime: metav1.Now(),
		})
		runner.RegisterFixtures(p)
		for _, v := range secrets {
			runner.RegisterFixtures(v)
		}

		transport.RegisterResponder(
			http.MethodPost,
			"https://api.github.com/app/installations/2/access_tokens",
			httpmock.NewStringResponder(http.StatusOK, `{"token":"mocktoken"}`),
		)
		transport.RegisterRegexpResponder(
			http.MethodDelete,
			regexp.MustCompile(`/repos/f110/heimdallr/hooks/1234$`),
			httpmock.NewStringResponder(http.StatusNoContent, ""),
		)

		err = runner.Finalize(controller, backend)
		require.NoError(t, err)

		updated, err := runner.Client.ProxyV1alpha2().Backends(backend.Namespace).Get(context.TODO(), backend.Name, metav1.GetOptions{})
		require.NoError(t, err)
		runner.AssertUpdateAction(t, "", updated)
		runner.AssertUpdateAction(t, "status", updated)
		runner.AssertNoUnexpectedAction(t)
	})
}

func ExpectCall(t *testing.T, callInfo map[string]int, method, url string) {
	if _, ok := callInfo[fmt.Sprintf("%s %s", method, url)]; !ok {
		t.Errorf("Expect call %s %s", method, url)
	}
}

func githubControllerFixtures(t *testing.T, name string) (*proxyv1alpha2.Proxy, *proxyv1alpha2.Backend, []*corev1.Secret) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	buf := new(bytes.Buffer)
	err = pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	require.NoError(t, err)

	p := proxy.Factory(nil,
		k8sfactory.Name("test"),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		proxy.Domain("test-proxy.f110.dev"),
	)
	p.Status.GithubWebhookSecretName = "github-webhook-secret"

	b := proxy.BackendFactory(nil,
		k8sfactory.Name(name),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		proxy.Layer("test"),
		proxy.Permission(proxy.PermissionFactory(nil,
			proxy.Name("all"),
			proxy.Location("Any", "/hook"),
			proxy.Webhook("github"),
			proxy.GitHubWebhookConfiguration(&proxyv1alpha2.GitHubHookConfiguration{
				Path:                 "/hook",
				ContentType:          "application/json",
				Events:               []string{"push"},
				CredentialSecretName: "github-secret",
				Repositories:         []string{"f110/heimdallr"},
				AppIdKey:             "appid",
				InstallationIdKey:    "installationid",
				PrivateKeyKey:        "privatekey",
			}),
		)),
	)
	b.Status.DeployedBy = []*proxyv1alpha2.ProxyReference{
		{Name: p.Name, Namespace: metav1.NamespaceDefault, Url: fmt.Sprintf("https://test.test.%s", p.Spec.Domain)},
	}

	s := k8sfactory.SecretFactory(nil,
		k8sfactory.Name("github-secret"),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.Data("appid", []byte("1")),
		k8sfactory.Data("installationid", []byte("2")),
		k8sfactory.Data("privatekey", buf.Bytes()),
	)
	webhookSecret := k8sfactory.SecretFactory(nil,
		k8sfactory.Name("github-webhook-secret"),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.Data(githubWebhookSecretFilename, []byte("test")),
	)

	return p, b, []*corev1.Secret{s, webhookSecret}
}
