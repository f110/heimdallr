package operator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"
	"go.f110.dev/kubeproto/go/k8stestingclient"

	"go.f110.dev/heimdallr/pkg/k8s/api/proxy"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxyv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/client/testingclient"
	"go.f110.dev/heimdallr/pkg/k8s/controllers"
	"go.f110.dev/heimdallr/pkg/k8s/thirdpartyclient/testingthirdpartyclient"
)

func TestUpgradeManagedFields(t *testing.T) {
	entry := func(manager string, operation metav1.ManagedFieldsOperationType, subresource, fields string) metav1.ManagedFieldsEntry {
		return metav1.ManagedFieldsEntry{
			Manager:     manager,
			Operation:   operation,
			APIVersion:  "apps/v1",
			FieldsType:  "FieldsV1",
			FieldsV1:    &metav1.FieldsV1{Raw: []byte(fields)},
			Subresource: subresource,
		}
	}
	update := metav1.ManagedFieldsOperationTypeUpdate
	apply := metav1.ManagedFieldsOperationTypeApply
	restartedAt := entry("kubectl-rollout", update, "", `{"f:spec":{"f:template":{"f:metadata":{"f:annotations":{"f:kubectl.kubernetes.io/restartedAt":{}}}}}}`)
	status := entry("kube-controller-manager", update, "status", `{"f:status":{"f:replicas":{}}}`)

	t.Run("NoLegacyManager", func(t *testing.T) {
		_, upgraded, err := upgradeManagedFields([]metav1.ManagedFieldsEntry{
			entry(controllers.FieldManager, apply, "", `{"f:spec":{"f:replicas":{}}}`),
			restartedAt,
			status,
		})
		require.NoError(t, err)
		assert.False(t, upgraded)
	})

	t.Run("TransferOwnership", func(t *testing.T) {
		got, upgraded, err := upgradeManagedFields([]metav1.ManagedFieldsEntry{
			entry("heimdallrcontroller", update, "", `{"f:metadata":{"f:finalizers":{".":{},"v:\"example.com/finalizer\"":{}}},"f:spec":{"f:replicas":{}}}`),
			entry("Go-http-client", update, "", `{"f:spec":{"f:minReadySeconds":{}}}`),
			restartedAt,
			status,
		})
		require.NoError(t, err)
		require.True(t, upgraded)

		managers := make(map[string]metav1.ManagedFieldsEntry)
		for _, v := range got {
			managers[v.Manager+"/"+string(v.Operation)+"/"+v.Subresource] = v
		}
		require.Len(t, managers, 3)
		applied, ok := managers[controllers.FieldManager+"/Apply/"]
		require.True(t, ok)
		assert.JSONEq(t, `{"f:spec":{"f:minReadySeconds":{},"f:replicas":{}}}`, string(applied.FieldsV1.Raw))
		assert.Equal(t, restartedAt, managers["kubectl-rollout/Update/"])
		assert.Equal(t, status, managers["kube-controller-manager/Update/status"])
	})
}

func TestMigrateManagedFields(t *testing.T) {
	coreClient := k8stestingclient.NewSet()
	m := &mainProcess{
		ctx:              t.Context(),
		coreClient:       &coreClient.Set,
		client:           &testingclient.NewSet().Set,
		thirdPartyClient: &testingthirdpartyclient.NewSet().Set,
	}
	legacyEntries := []metav1.ManagedFieldsEntry{
		{
			Manager:    "Go-http-client",
			Operation:  metav1.ManagedFieldsOperationTypeUpdate,
			APIVersion: "v1",
			FieldsType: "FieldsV1",
			FieldsV1:   &metav1.FieldsV1{Raw: []byte(`{"f:data":{".":{},"f:a":{},"f:b":{}},"f:metadata":{"f:finalizers":{".":{},"v:\"example.com/finalizer\"":{}}}}`)},
		},
		{
			Manager:    "kubectl",
			Operation:  metav1.ManagedFieldsOperationTypeUpdate,
			APIVersion: "v1",
			FieldsType: "FieldsV1",
			FieldsV1:   &metav1.FieldsV1{Raw: []byte(`{"f:metadata":{"f:annotations":{".":{},"f:example.com/annotation":{}}}}`)},
		},
	}
	configMap := func(name string, data map[string]string) *corev1.ConfigMap {
		return &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: metav1.NamespaceDefault},
			Data:       data,
		}
	}
	// The older operator created the object and added the finalizer by Update. Then kubectl added the annotation.
	controlled := configMap("controlled", map[string]string{"a": "1", "b": "2"})
	controlled.OwnerReferences = []metav1.OwnerReference{
		metav1.NewControllerRef(metav1.ObjectMeta{Name: "test", UID: "uid"}, proxyv1alpha2.SchemaGroupVersion.WithKind("Proxy")),
	}
	controlled.Finalizers = []string{"example.com/finalizer"}
	controlled.Annotations = map[string]string{"example.com/annotation": "value"}
	controlled.ManagedFields = legacyEntries
	require.NoError(t, coreClient.Tracker().Add(controlled))
	// The object which is created by the other program.
	other := configMap("other", map[string]string{"a": "1", "b": "2"})
	other.ManagedFields = legacyEntries
	require.NoError(t, coreClient.Tracker().Add(other))

	require.NoError(t, m.migrateManagedFields(t.Context()))

	managersOf := func(obj *corev1.ConfigMap) []string {
		managers := make([]string, 0)
		for _, v := range obj.ManagedFields {
			managers = append(managers, v.Manager+"/"+string(v.Operation))
		}
		return managers
	}
	got, err := coreClient.CoreV1.GetConfigMap(t.Context(), metav1.NamespaceDefault, "other", metav1.GetOptions{})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"Go-http-client/Update", "kubectl/Update"}, managersOf(got))

	applied, err := coreClient.CoreV1.ApplyConfigMap(
		t.Context(),
		configMap("controlled", map[string]string{"a": "1"}),
		metav1.ApplyOptions{FieldManager: controllers.FieldManager, Force: true},
	)
	require.NoError(t, err)
	// The field which the older operator set but the operator no longer sets is removed.
	assert.Equal(t, map[string]string{"a": "1"}, applied.Data)
	// The fields of the other managers and finalizers are kept.
	assert.Equal(t, "value", applied.Annotations["example.com/annotation"])
	assert.Equal(t, []string{"example.com/finalizer"}, applied.Finalizers)
	assert.ElementsMatch(t, []string{controllers.FieldManager + "/Apply", "kubectl/Update"}, managersOf(applied))
}

func TestIsCreatedByIngressController(t *testing.T) {
	backend := &proxyv1alpha2.Backend{ObjectMeta: metav1.ObjectMeta{Name: "test"}}
	assert.False(t, isCreatedByIngressController(backend))

	backend.Annotations = map[string]string{proxy.AnnotationKeyIngressName: "default/test"}
	assert.True(t, isCreatedByIngressController(backend))
}
