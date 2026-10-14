package test

import (
	"context"
	"testing"

	"go.f110.dev/heimdallr/operator/e2e/framework"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
	"go.f110.dev/heimdallr/pkg/testing/btesting"
)

func TestNamespacedOperator(t *testing.T) {
	t.Parallel()
	f := framework.New(t, RESTConfig)
	defer f.Execute()

	const namespace = "e2e-namespaced-operator"
	f.Describe("Operator that watches only the namespace", func(s *btesting.Scenario) {
		s.Context("creates a new etcd cluster in the namespace", func(s *btesting.Scenario) {
			s.Subject(func(_ context.Context, m *btesting.Matcher) {
				f.DeployNamespacedOperator(m, namespace)
				f.EtcdClusters.Setup(m, k8sfactory.Name("namespaced"), k8sfactory.Namespace(namespace))
			})
			s.Defer(func() {
				f.EtcdClusters.EtcdCluster("namespaced").Destroy(f.Client())
				f.DeleteNamespacedOperator(namespace)
			})

			s.It("should have 3 pods", func(_ context.Context, m *btesting.Matcher) {
				f.EtcdClusters.EtcdCluster("namespaced").NumOfPods(m, 3)
			})
		})
	})
}
