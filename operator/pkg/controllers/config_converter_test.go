package controllers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeinformers "k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/yaml"

	proxyv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha2"
	"go.f110.dev/heimdallr/pkg/config/configv2"
)

func TestConfigConverter_Proxy(t *testing.T) {
	cases := []struct {
		Description string
		Backends    []*proxyv1alpha2.Backend
		Expect      []*configv2.Backend
	}{
		{
			Description: "HTTP backend via Service",
			Backends: []*proxyv1alpha2.Backend{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test",
					},
					Spec: proxyv1alpha2.BackendSpec{
						HTTP: []*proxyv1alpha2.BackendHTTPSpec{
							{
								Path: "/",
								ServiceSelector: &proxyv1alpha2.ServiceSelector{
									Name:      "test-svc",
									Namespace: metav1.NamespaceDefault,
									Port:      "http",
									LabelSelector: metav1.LabelSelector{
										MatchLabels: map[string]string{"k8s-app": "test"},
									},
								},
							},
						},
						Permissions: []proxyv1alpha2.Permission{
							{Name: "all", Locations: []proxyv1alpha2.Location{{Any: "/"}}},
						},
					},
				},
			},
			Expect: []*configv2.Backend{
				{
					Name: "test",
					HTTP: []*configv2.HTTPBackend{
						{
							Path:     "/",
							Upstream: "http://test-svc.default.svc:8080",
						},
					},
					Permissions: []*configv2.Permission{
						{Name: "all", Locations: []configv2.Location{{Any: "/"}}},
					},
				},
			},
		},
		{
			Description: "HTTP backend via connector",
			Backends: []*proxyv1alpha2.Backend{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test",
					},
					Spec: proxyv1alpha2.BackendSpec{
						HTTP: []*proxyv1alpha2.BackendHTTPSpec{
							{
								Path:  "/",
								Agent: true,
							},
						},
						Permissions: []proxyv1alpha2.Permission{
							{Name: "all", Locations: []proxyv1alpha2.Location{{Any: "/"}}},
						},
					},
				},
			},
			Expect: []*configv2.Backend{
				{
					Name: "test",
					HTTP: []*configv2.HTTPBackend{
						{Path: "/", Agent: true},
					},
					Permissions: []*configv2.Permission{
						{Name: "all", Locations: []configv2.Location{{Any: "/"}}},
					},
				},
			},
		},
		{
			Description: "Socket backend via Service",
			Backends: []*proxyv1alpha2.Backend{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node",
					},
					Spec: proxyv1alpha2.BackendSpec{
						Layer: "ssh",
						Socket: &proxyv1alpha2.BackendSocketSpec{
							ServiceSelector: &proxyv1alpha2.ServiceSelector{
								Namespace: metav1.NamespaceDefault,
								Port:      "http",
								LabelSelector: metav1.LabelSelector{
									MatchLabels: map[string]string{"k8s-app": "test"},
								},
							},
						},
					},
				},
			},
			Expect: []*configv2.Backend{
				{
					Name: "node.ssh",
					Socket: &configv2.SocketBackend{
						Upstream: "tcp://test-svc.default.svc:8080",
					},
					Permissions: []*configv2.Permission{},
				},
			},
		},
		{
			Description: "Socket backend via connector",
			Backends: []*proxyv1alpha2.Backend{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node",
					},
					Spec: proxyv1alpha2.BackendSpec{
						Layer: "ssh",
						Socket: &proxyv1alpha2.BackendSocketSpec{
							Agent: true,
						},
					},
				},
			},
			Expect: []*configv2.Backend{
				{
					Name: "node.ssh",
					Socket: &configv2.SocketBackend{
						Agent: true,
					},
					Permissions: []*configv2.Permission{},
				},
			},
		},
	}
	coreClient := k8sfake.NewSimpleClientset()
	coreSharedInformerFactory := kubeinformers.NewSharedInformerFactory(coreClient, 30*time.Second)
	coreSharedInformerFactory.Core().V1().Services().Informer().GetIndexer().Add(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-svc",
			Namespace: metav1.NamespaceDefault,
			Labels:    map[string]string{"k8s-app": "test"},
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 8080,
				},
			},
		},
	})
	serviceLister := coreSharedInformerFactory.Core().V1().Services().Lister()

	for _, tt := range cases {
		t.Run(tt.Description, func(t *testing.T) {
			buf, err := ConfigConverter{}.Proxy(tt.Backends, serviceLister)
			require.NoError(t, err)

			got := make([]*configv2.Backend, 0)
			err = yaml.Unmarshal(buf, &got)
			require.NoError(t, err)

			require.Len(t, got, len(tt.Expect))
			for i := range tt.Expect {
				assert.Equal(t, tt.Expect[i], got[i])
			}
		})
	}
}
