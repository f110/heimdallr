package e2eutil

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"go.f110.dev/heimdallr/pkg/cert"
)

const testAllInOneManifest = `apiVersion: v1
kind: Namespace
metadata:
  name: heimdallr
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: backends.proxy.f110.dev
spec:
  group: proxy.f110.dev
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: heimdallr
  namespace: heimdallr
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: leader-election-role
  namespace: heimdallr
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: heimdallr
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: leader-election-rolebinding
  namespace: heimdallr
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: leader-election-role
subjects:
- kind: ServiceAccount
  name: heimdallr
  namespace: heimdallr
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: manager-role-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: heimdallr
subjects:
- kind: ServiceAccount
  name: heimdallr
  namespace: heimdallr
---
apiVersion: v1
kind: Secret
metadata:
  name: webhook-cert
  namespace: heimdallr
stringData:
  webhook.crt: cert
  webhook.key: key
---
apiVersion: v1
kind: Service
metadata:
  name: webhook
  namespace: heimdallr
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: heimdallr-operator
  namespace: heimdallr
spec:
  template:
    spec:
      containers:
      - name: operator
        args:
        - --lease-lock-name=operator
        - --namespace=default
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: heimdallr-operator-webhook
webhooks:
- name: heimdallr.f110.dev
  clientConfig:
    service:
      name: webhook
      namespace: heimdallr
      path: /validate
    caBundle: Y2E=
`

func TestNamespacedOperatorManifest(t *testing.T) {
	caCert, caKey, err := cert.CreateCertificateAuthority("test", "", "", "", "ecdsa")
	require.NoError(t, err)

	objs, err := NamespacedOperatorManifest([]byte(testAllInOneManifest), "op", caCert, caKey)
	require.NoError(t, err)

	got := make(map[string]*unstructured.Unstructured)
	for _, v := range objs {
		got[v.GetKind()] = v
	}
	require.Len(t, got, len(objs))
	assert.NotContains(t, got, "CustomResourceDefinition")
	assert.Equal(t, "Namespace", objs[0].GetKind())
	assert.Equal(t, "op", objs[0].GetName())

	for _, kind := range []string{"ServiceAccount", "Role", "RoleBinding", "Secret", "Service", "Deployment"} {
		assert.Equal(t, "op", got[kind].GetNamespace(), kind)
	}

	assert.Equal(t, "heimdallr-op", got["ClusterRole"].GetName())
	assert.Equal(t, "manager-role-binding-op", got["ClusterRoleBinding"].GetName())
	roleRef, _, _ := unstructured.NestedString(got["ClusterRoleBinding"].Object, "roleRef", "name")
	assert.Equal(t, "heimdallr-op", roleRef)
	for _, kind := range []string{"RoleBinding", "ClusterRoleBinding"} {
		subjects, _, _ := unstructured.NestedSlice(got[kind].Object, "subjects")
		require.Len(t, subjects, 1)
		assert.Equal(t, "op", subjects[0].(map[string]any)["namespace"], kind)
	}

	containers, _, _ := unstructured.NestedSlice(got["Deployment"].Object, "spec", "template", "spec", "containers")
	args, _, _ := unstructured.NestedStringSlice(containers[0].(map[string]any), "args")
	assert.Equal(t, []string{"--lease-lock-name=operator", "--namespace=op"}, args)

	vwc := got["ValidatingWebhookConfiguration"]
	assert.Equal(t, "heimdallr-operator-webhook-op", vwc.GetName())
	webhooks, _, _ := unstructured.NestedSlice(vwc.Object, "webhooks")
	require.Len(t, webhooks, 1)
	webhook := webhooks[0].(map[string]any)
	serviceNamespace, _, _ := unstructured.NestedString(webhook, "clientConfig", "service", "namespace")
	assert.Equal(t, "op", serviceNamespace)
	selector, _, _ := unstructured.NestedStringMap(webhook, "namespaceSelector", "matchLabels")
	assert.Equal(t, map[string]string{"kubernetes.io/metadata.name": "op"}, selector)
	caBundle, _, _ := unstructured.NestedString(webhook, "clientConfig", "caBundle")
	caBundlePEM, err := base64.StdEncoding.DecodeString(caBundle)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caBundlePEM))
	serverCertPEM, _, _ := unstructured.NestedString(got["Secret"].Object, "stringData", "webhook.crt")
	block, _ := pem.Decode([]byte(serverCertPEM))
	require.NotNil(t, block)
	serverCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	_, err = serverCert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "webhook.op.svc"})
	assert.NoError(t, err)
	serverKeyPEM, _, _ := unstructured.NestedString(got["Secret"].Object, "stringData", "webhook.key")
	assert.Contains(t, serverKeyPEM, "PRIVATE KEY")
}
