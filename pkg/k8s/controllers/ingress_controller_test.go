package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"
	"go.f110.dev/kubeproto/go/apis/networkingv1"

	"go.f110.dev/heimdallr/pkg/k8s/api/proxy"
	"go.f110.dev/heimdallr/pkg/k8s/controllers/controllertest"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
)

func TestIngressController(t *testing.T) {
	t.Run("CreateBackend", func(t *testing.T) {
		t.Parallel()

		runner := controllertest.NewTestRunner()
		controller := NewIngressController(
			runner.CoreSharedInformerFactory,
			runner.SharedInformerFactory,
			&runner.CoreClient.Set,
			runner.Client.ProxyV1alpha2,
			runner.K8sCoreClient,
		)

		ingClass, ing, svc, svcWeb := ingressControllerFixtures()
		runner.RegisterFixtures(ingClass, svc, svcWeb)

		err := runner.Reconcile(controller, ing)
		require.NoError(t, err)

		updatedB, err := runner.Client.ProxyV1alpha2.GetBackend(context.Background(), ing.Namespace, ing.Name, metav1.GetOptions{})
		require.NoError(t, err)
		assert.Equal(t, ingClass.Labels, updatedB.Labels)
		assert.Equal(t, ing.Spec.Rules[0].Host, updatedB.Spec.FQDN)
		assert.True(t, updatedB.Spec.DisableAuthn)
		require.Len(t, updatedB.Spec.HTTP, 2)
		assert.Equal(t, svc.Name, updatedB.Spec.HTTP[0].ServiceSelector.Name)
		assert.Equal(t, svcWeb.Name, updatedB.Spec.HTTP[1].ServiceSelector.Name)

		//runner.AssertUpdateAction(t, "status", ing)
		runner.AssertCreateAction(t, proxy.BackendFactory(nil, k8sfactory.Namef("%s", ing.Name), k8sfactory.Namespace(ing.Namespace)))
		runner.AssertNoUnexpectedAction(t)
	})
}

func ingressControllerFixtures() (*networkingv1.IngressClass, *networkingv1.Ingress, *corev1.Service, *corev1.Service) {
	// IngressClass is a cluster scope
	ingClass := k8sfactory.IngressClassFactory(nil,
		k8sfactory.Name("test"),
		k8sfactory.Label("instance", "test"),
		k8sfactory.Controller(ingressClassControllerName),
	)

	svc := k8sfactory.ServiceFactory(nil,
		k8sfactory.Name("api"),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.ClusterIP,
		k8sfactory.MatchLabelSelector(map[string]string{"k8s-app": "api"}),
		k8sfactory.Port("http", corev1.ProtocolTCP, 80),
	)

	svcWeb := k8sfactory.ServiceFactory(nil,
		k8sfactory.Name("web"),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.ClusterIP,
		k8sfactory.MatchLabelSelector(map[string]string{"k8s-app": "web"}),
		k8sfactory.Port("http", corev1.ProtocolTCP, 80),
	)

	ingRule := k8sfactory.IngressRuleFactory(nil,
		k8sfactory.Host("test.f110.dev"),
		k8sfactory.Path(
			"/api",
			networkingv1.PathTypeImplementationSpecific,
			svc,
			"http",
		),
		k8sfactory.Path(
			"/web",
			networkingv1.PathTypeImplementationSpecific,
			svcWeb,
			"http",
		),
	)
	ing := k8sfactory.IngressFactory(nil,
		k8sfactory.Name("test"),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.IngressClass(ingClass),
		k8sfactory.Rule(ingRule),
	)

	return ingClass, ing, svc, svcWeb
}
