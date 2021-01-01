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
	cases := []struct {
		In     string
		Expect *proxyv1alpha2.Backend
	}{
		{
			In: `apiVersion: proxy.f110.dev/v1alpha1
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
`,
			Expect: &proxyv1alpha2.Backend{
				Spec: proxyv1alpha2.BackendSpec{
					HTTP: []*proxyv1alpha2.BackendHTTPSpec{
						{
							Path: "/",
						},
					},
					Permissions: []proxyv1alpha2.Permission{
						{
							Name: "all",
						},
					},
				},
			},
		},
		{
			In: `apiVersion: proxy.f110.dev/v1alpha1
kind: Backend
metadata:
  name: raptor
  namespace: heimdallr
  labels:
    instance: global
spec:
  layer: ssh
  agent: true
  upstream: tcp://127.0.0.1:22`,
			Expect: &proxyv1alpha2.Backend{
				Spec: proxyv1alpha2.BackendSpec{
					Socket: &proxyv1alpha2.BackendSocketSpec{
						Agent: true,
					},
				},
			},
		},
	}

	for _, tt := range cases {
		obj := decodeYAML(t, tt.In)

		v, err := V1Alpha1BackendToV1Alpha2Backend(obj)
		require.NoError(t, err)
		out, ok := v.(*proxyv1alpha2.Backend)
		require.True(t, ok)

		if tt.Expect.Spec.HTTP != nil {
			require.NotNil(t, out.Spec.HTTP)
			assert.Len(t, out.Spec.HTTP, len(tt.Expect.Spec.HTTP))
		}
		if tt.Expect.Spec.Socket != nil {
			require.NotNil(t, out.Spec.Socket)
			assert.Equal(t, tt.Expect.Spec.Socket.Upstream, out.Spec.Socket.Upstream)
			assert.Equal(t, tt.Expect.Spec.Socket.Agent, out.Spec.Socket.Agent)
			if tt.Expect.Spec.Socket.ServiceSelector == nil {
				assert.Nil(t, out.Spec.Socket.ServiceSelector)
			}
		}
		assert.Len(t, out.Spec.Permissions, len(tt.Expect.Spec.Permissions))
	}
}

func TestV1Alpha2BackendToV1Alpha1Backend(t *testing.T) {
	cases := []struct {
		In     string
		Expect *proxyv1alpha1.Backend
	}{
		{
			In: `apiVersion: proxy.f110.dev/v1alpha2
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
        - any: /`,
			Expect: &proxyv1alpha1.Backend{
				Spec: proxyv1alpha1.BackendSpec{
					Layer: "tools",
					ServiceSelector: proxyv1alpha1.ServiceSelector{
						Port: "https-gui",
					},
					Permissions: []proxyv1alpha1.Permission{
						{Name: "all", Locations: []proxyv1alpha1.Location{{Any: "/"}}},
					},
				},
			},
		},
		{
			In: `apiVersion: proxy.f110.dev/v1alpha2
kind: Backend
metadata:
  name: raptor
spec:
  layer: ssh
  socket:
    agent: true`,
			Expect: &proxyv1alpha1.Backend{
				Spec: proxyv1alpha1.BackendSpec{
					Layer:  "ssh",
					Agent:  true,
					Socket: true,
				},
			},
		},
		{
			In: `apiVersion: proxy.f110.dev/v1alpha2
kind: Backend
metadata:
  name: build-dev
  namespace: build-dev
spec:
  http:
  - path: /api
    serviceSelector:
      matchLabels:
        app.kubernetes.io/name: build
      namespace: build-dev
      port: api
      scheme: http
  - path: /
    serviceSelector:
      matchLabels:
        app.kubernetes.io/name: build
      namespace: build-dev
      port: http
      scheme: http
  layer: internal
  permissions:
  - locations:
    - any: /
    name: all
  - name: webhook
    webhook: github
    webhookConfiguration:
      github:
        appIdKey: appid
        contentType: json
        credentialSecretName: github-app
        events:
        - push
        installationIdKey: installationid
        path: /api/webhook
        privateKeyKey: privatekey.pem
        repositories:
        - f110/sandbox`,
			Expect: &proxyv1alpha1.Backend{
				Spec: proxyv1alpha1.BackendSpec{
					Layer: "internal",
					ServiceSelector: proxyv1alpha1.ServiceSelector{
						Port: "api",
					},
					Permissions: []proxyv1alpha1.Permission{
						{Name: "all", Locations: []proxyv1alpha1.Location{{Any: "/"}}},
						{Name: "webhook", Locations: []proxyv1alpha1.Location{{Any: "/api/webhook"}}},
					},
				},
			},
		},
		{
			In: `apiVersion: proxy.f110.dev/v1alpha2
kind: Backend
metadata:
  name: build
  labels:
    instance: global
spec:
  layer: webhook
  http:
    - path: /
      agent: true
  permissions:
    - name: all
      locations:
        - any: /`,
			Expect: &proxyv1alpha1.Backend{
				Spec: proxyv1alpha1.BackendSpec{
					Layer:    "webhook",
					Agent:    true,
					Upstream: "tcp://127.0.0.1:80",
					Permissions: []proxyv1alpha1.Permission{
						{Name: "all", Locations: []proxyv1alpha1.Location{{Any: "/"}}},
					},
				},
			},
		},
	}

	for _, tt := range cases {
		obj := decodeYAML(t, tt.In)

		v, err := V1Alpha2BackendToV1Alpha1Backend(obj)
		require.NoError(t, err)
		out, ok := v.(*proxyv1alpha1.Backend)
		require.True(t, ok)

		assert.Equal(t, tt.Expect.Spec.Layer, out.Spec.Layer)
		assert.Equal(t, tt.Expect.Spec.Agent, out.Spec.Agent)
		assert.Equal(t, tt.Expect.Spec.Socket, out.Spec.Socket)
		assert.Equal(t, tt.Expect.Spec.ServiceSelector.Port, out.Spec.ServiceSelector.Port)
		assert.Equal(t, tt.Expect.Spec.Upstream, out.Spec.Upstream)
		assert.Len(t, out.Spec.Permissions, len(tt.Expect.Spec.Permissions))
	}
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
