package webhook

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestServer_Validate(t *testing.T) {
	cases := []struct {
		Name        string
		Kind        metav1.GroupVersionKind
		SubResource string
		Object      string
		Allowed     bool
	}{
		{
			Name:    "v3.3 is not supported",
			Kind:    metav1.GroupVersionKind{Group: "etcd.f110.dev", Version: "v1alpha2", Kind: "EtcdCluster"},
			Object:  `{"spec":{"version":"v3.3.25"}}`,
			Allowed: false,
		},
		{
			Name:    "v3.4",
			Kind:    metav1.GroupVersionKind{Group: "etcd.f110.dev", Version: "v1alpha2", Kind: "EtcdCluster"},
			Object:  `{"spec":{"version":"v3.4.0"}}`,
			Allowed: true,
		},
		{
			Name:    "v3.4 that has the shell",
			Kind:    metav1.GroupVersionKind{Group: "etcd.f110.dev", Version: "v1alpha2", Kind: "EtcdCluster"},
			Object:  `{"spec":{"version":"v3.4.23"}}`,
			Allowed: true,
		},
		{
			Name:    "v3.4 that doesn't have the shell",
			Kind:    metav1.GroupVersionKind{Group: "etcd.f110.dev", Version: "v1alpha2", Kind: "EtcdCluster"},
			Object:  `{"spec":{"version":"v3.4.24"}}`,
			Allowed: false,
		},
		{
			Name:    "v3.5",
			Kind:    metav1.GroupVersionKind{Group: "etcd.f110.dev", Version: "v1alpha2", Kind: "EtcdCluster"},
			Object:  `{"spec":{"version":"v3.5.0"}}`,
			Allowed: true,
		},
		{
			Name:    "v3.6",
			Kind:    metav1.GroupVersionKind{Group: "etcd.f110.dev", Version: "v1alpha2", Kind: "EtcdCluster"},
			Object:  `{"spec":{"version":"v3.6.15"}}`,
			Allowed: true,
		},
		{
			Name:    "Default version",
			Kind:    metav1.GroupVersionKind{Group: "etcd.f110.dev", Version: "v1alpha2", Kind: "EtcdCluster"},
			Object:  `{"spec":{}}`,
			Allowed: true,
		},
		{
			Name:    "Invalid version",
			Kind:    metav1.GroupVersionKind{Group: "etcd.f110.dev", Version: "v1alpha2", Kind: "EtcdCluster"},
			Object:  `{"spec":{"version":"latest"}}`,
			Allowed: false,
		},
		{
			Name:    "v1alpha1",
			Kind:    metav1.GroupVersionKind{Group: "etcd.f110.dev", Version: "v1alpha1", Kind: "EtcdCluster"},
			Object:  `{"spec":{"version":"v3.3.25"}}`,
			Allowed: false,
		},
		{
			Name:        "Status subresource",
			Kind:        metav1.GroupVersionKind{Group: "etcd.f110.dev", Version: "v1alpha2", Kind: "EtcdCluster"},
			SubResource: "status",
			Object:      `{"spec":{"version":"v3.3.25"}}`,
			Allowed:     true,
		},
		{
			Name:    "Other kind",
			Kind:    metav1.GroupVersionKind{Group: "proxy.f110.dev", Version: "v1alpha2", Kind: "Proxy"},
			Object:  `{"spec":{"version":"v0.1.0"}}`,
			Allowed: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			review := &admissionv1.AdmissionReview{
				TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
				Request: &admissionv1.AdmissionRequest{
					UID:         "test",
					Kind:        tc.Kind,
					SubResource: tc.SubResource,
					Operation:   admissionv1.Create,
					Object:      runtime.RawExtension{Raw: []byte(tc.Object)},
				},
			}
			body, err := json.Marshal(review)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			NewServer(":0", "", "").Validate(w, req)
			require.Equal(t, http.StatusOK, w.Code)

			res := &admissionv1.AdmissionReview{}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), res))
			require.NotNil(t, res.Response)
			assert.Equal(t, review.Request.UID, res.Response.UID)
			assert.Equal(t, tc.Allowed, res.Response.Allowed)
			if !tc.Allowed {
				require.NotNil(t, res.Response.Result)
				assert.NotEmpty(t, res.Response.Result.Message)
			}
		})
	}
}
