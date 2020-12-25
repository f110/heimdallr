package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIngressController(t *testing.T) {
	t.Run("CreateBackend", func(t *testing.T) {
		t.Parallel()
		f := newIngressControllerTestRunner(t)

		ingClass, ing, svc, svcWeb := ingressControllerFixtures()
		f.RegisterIngressClassFixture(ingClass)
		f.RegisterIngressFixture(ing)
		f.RegisterServiceFixture(svc, svcWeb)

		f.ExpectUpdateIngress()
		f.ExpectCreateBackend()
		f.Run(t, ing)

		updatedB, err := f.client.ProxyV1alpha2().Backends(ing.Namespace).Get(context.TODO(), ing.Name, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, ingClass.Labels, updatedB.Labels)
		assert.Equal(t, ing.Spec.Rules[0].Host, updatedB.Spec.FQDN)
		assert.True(t, updatedB.Spec.DisableAuthn)
		require.Len(t, updatedB.Spec.HTTP, 2)
		assert.Equal(t, svc.Name, updatedB.Spec.HTTP[0].ServiceSelector.Name)
		assert.Equal(t, svcWeb.Name, updatedB.Spec.HTTP[1].ServiceSelector.Name)
	})
}

func ingressControllerFixtures() (*networkingv1.IngressClass, *networkingv1.Ingress, *corev1.Service, *corev1.Service) {
	// IngressClass is a cluster scope
	ingClass := &networkingv1.IngressClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			Labels: map[string]string{
				"instance": "test",
			},
		},
		Spec: networkingv1.IngressClassSpec{
			Controller: ingressClassControllerName,
		},
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "api",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"k8s-app": "api",
			},
			Ports: []corev1.ServicePort{
				{
					Name: "http",
					Port: 80,
				},
			},
		},
	}

	svcWeb := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Selector: map[string]string{
				"k8s-app": "web",
			},
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 80},
			},
		},
	}

	pt := networkingv1.PathTypeImplementationSpecific
	ing := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &ingClass.Name,
			Rules: []networkingv1.IngressRule{
				{
					Host: "test.f110.dev",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api",
									PathType: &pt,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: svc.Name,
											Port: networkingv1.ServiceBackendPort{
												Name: "http",
											},
										},
									},
								},
								{
									Path:     "/web",
									PathType: &pt,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: svcWeb.Name,
											Port: networkingv1.ServiceBackendPort{
												Name: "http",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	return ingClass, ing, svc, svcWeb
}
