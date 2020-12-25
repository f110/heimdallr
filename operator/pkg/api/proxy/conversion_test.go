package proxy

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"

	proxyv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha1"
	proxyv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha2"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/logger"
)

func TestMain(m *testing.M) {
	flag.Parse()

	level := "warn"
	if testing.Verbose() {
		level = "debug"
	}
	if err := logger.Init(&configv2.Logger{Level: level, Encoding: "console"}); err != nil {
		fmt.Fprintf(os.Stderr, "failure initialize logger: %+v\n", err)
		os.Exit(1)
	}

	m.Run()
}

func TestV1Alpha1ProxyToV1Alpha2Proxy(t *testing.T) {
	in := `apiVersion: proxy.f110.dev/v1alpha1
kind: Proxy
metadata:
  name: global
  namespace: heimdallr
spec:
  replicas: 3
  version: v0.11.0-rc.2
  domain: x.f110.dev
  port: 443
  httpPort: 80
  loadBalancerIP: 192.168.100.129
  organization: f110
  administratorUnit: admin
  backendSelector:
    matchLabels:
      instance: global
  roleSelector:
    matchLabels:
      instance: global
  issuerRef:
    name: lets-encrypt
    kind: ClusterIssuer
  identityProvider:
    provider: google
    clientId: foobar
    clientSecretRef:
      name: client-secret
      key: client_secret
    redirectUrl: https://local-proxy.f110.dev/auth/callback
  rootUsers:
    - fmhrit@gmail.com
  session:
    type: secure_cookie
    keySecretRef:
      name: cookie-secret
  monitor:
    prometheusMonitoring: true
    labels:
      k8s-app: heimdallr
  defragment:
    schedule: "18 13 * * *"`

	obj := decodeYAML(t, in)

	v, err := V1Alpha1ProxyToV1Alpha2Proxy(obj)
	require.NoError(t, err)
	out, ok := v.(*proxyv1alpha2.Proxy)
	require.True(t, ok)

	assert.Equal(t, "f110", out.Spec.CertificateAuthority.Local.Organization)
}

func TestV1Alpha1BackendToV1Alpha2Backend(t *testing.T) {
	in := `apiVersion: proxy.f110.dev/v1alpha1
kind: Backend
metadata:
  name: unifi
  namespace: unifi
  labels:
    instance: global
spec:
  layer: tools
  insecure: true
  serviceSelector:
    namespace: unifi
    scheme: https
    port: https-gui
    matchLabels:
      app.kubernetes.io/instance: unifi-controller
      role: gui
  permissions:
    - name: all
      locations:
        - any: /
`
	obj := decodeYAML(t, in)

	v, err := V1Alpha1BackendToV1Alpha2Backend(obj)
	require.NoError(t, err)
	out, ok := v.(*proxyv1alpha2.Backend)
	require.True(t, ok)

	assert.Len(t, out.Spec.HTTP, 1)
	assert.Len(t, out.Spec.Permissions, 1)
}

func TestV1Alpha2BackendToV1Alpha1Backend(t *testing.T) {
	in := `apiVersion: proxy.f110.dev/v1alpha2
kind: Backend
metadata:
  name: unifi
spec:
  layer: tools
  http:
    - path: /
      insecure: true
      serviceSelector:
        namespace: unifi
        scheme: https
        port: https-gui
        matchLabels:
          app.kubernetes.io/instance: unifi-controller
  permissions:
    - name: all
      locations:
        - any: /`

	obj := decodeYAML(t, in)

	v, err := V1Alpha2BackendToV1Alpha1Backend(obj)
	require.NoError(t, err)
	out, ok := v.(*proxyv1alpha1.Backend)
	require.True(t, ok)

	assert.Equal(t, "https-gui", out.Spec.ServiceSelector.Port)
	assert.Len(t, out.Spec.Permissions, 1)
}

func decodeYAML(t *testing.T, in string) runtime.Object {
	d := yaml.NewYAMLOrJSONDecoder(strings.NewReader(in), 4096)
	raw := runtime.RawExtension{}
	err := d.Decode(&raw)
	require.NoError(t, err)

	obj, _, err := unstructured.UnstructuredJSONScheme.Decode(raw.Raw, nil, nil)
	require.NoError(t, err)

	return obj
}
