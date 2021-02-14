package k8s

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func TestSelectCustomResourceDefinitions(t *testing.T) {
	objs := make([]*unstructured.Unstructured, 0)
	d := yaml.NewYAMLOrJSONDecoder(strings.NewReader(rawManifests), 4096)
	for {
		ext := runtime.RawExtension{}
		if err := d.Decode(&ext); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatal(err)
		}
		if len(ext.Raw) == 0 {
			continue
		}

		obj, _, err := unstructured.UnstructuredJSONScheme.Decode(ext.Raw, nil, nil)
		require.NoError(t, err)
		objs = append(objs, obj.(*unstructured.Unstructured))
	}

	crds, err := Objects(objs).SelectCustomResourceDefinitions()
	require.NoError(t, err)
	require.Len(t, crds, 2)
	assert.Equal(t, "roles.proxy.f110.dev", crds[0].Name)
	assert.Equal(t, "rolebindings.proxy.f110.dev", crds[1].Name)
}

const rawManifests = `apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    controller-gen.kubebuilder.io/version: (unknown)
  creationTimestamp: null
  name: roles.proxy.f110.dev
spec:
  group: proxy.f110.dev
  names:
    kind: Role
    listKind: RoleList
    plural: roles
    singular: role
  scope: Namespaced
  versions:
  - name: v1alpha1
    schema:
      openAPIV3Schema:
        description: Role is the Schema for the roles API
        properties:
          apiVersion:
            description: 'APIVersion defines the versioned schema of this representation
              of an object. Servers should convert recognized schemas to the latest
              internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
            type: string
          kind:
            description: 'Kind is a string value representing the REST resource this
              object represents. Servers may infer this from the endpoint the client
              submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
            type: string
          metadata:
            type: object
          spec:
            description: RoleSpec defines the desired state of Role
            properties:
              allowDashboard:
                type: boolean
              description:
                type: string
              title:
                type: string
            type: object
          status:
            description: RoleStatus defines the observed state of Role
            type: object
        type: object
    served: true
    storage: false
    subresources:
      status: {}
  - name: v1alpha2
    schema:
      openAPIV3Schema:
        description: Role is the Schema for the roles API
        properties:
          apiVersion:
            description: 'APIVersion defines the versioned schema of this representation
              of an object. Servers should convert recognized schemas to the latest
              internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
            type: string
          kind:
            description: 'Kind is a string value representing the REST resource this
              object represents. Servers may infer this from the endpoint the client
              submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
            type: string
          metadata:
            type: object
          spec:
            description: RoleSpec defines the desired state of Role
            properties:
              allowDashboard:
                type: boolean
              description:
                type: string
              title:
                type: string
            type: object
          status:
            description: RoleStatus defines the observed state of Role
            type: object
        type: object
    served: true
    storage: true
    subresources:
      status: {}
status:
  acceptedNames:
    kind: ""
    plural: ""
  conditions: []
  storedVersions: []
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  annotations:
    controller-gen.kubebuilder.io/version: (unknown)
  creationTimestamp: null
  name: rolebindings.proxy.f110.dev
spec:
  group: proxy.f110.dev
  names:
    kind: RoleBinding
    listKind: RoleBindingList
    plural: rolebindings
    singular: rolebinding
  scope: Namespaced
  versions:
  - name: v1alpha1
    schema:
      openAPIV3Schema:
        properties:
          apiVersion:
            description: 'APIVersion defines the versioned schema of this representation
              of an object. Servers should convert recognized schemas to the latest
              internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
            type: string
          kind:
            description: 'Kind is a string value representing the REST resource this
              object represents. Servers may infer this from the endpoint the client
              submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
            type: string
          metadata:
            type: object
          roleRef:
            properties:
              name:
                type: string
              namespace:
                type: string
            required:
            - name
            - namespace
            type: object
          subjects:
            items:
              properties:
                kind:
                  description: Kind of object. Value is "Backend" or "RpcPermission"
                  type: string
                name:
                  description: Name of object.
                  type: string
                namespace:
                  description: Namespace of object. If not set, will be use same namespace.
                  type: string
                permission:
                  description: Permission is the name of permission of backend.
                  type: string
              required:
              - kind
              - name
              type: object
            type: array
        required:
        - roleRef
        - subjects
        type: object
    served: true
    storage: false
  - name: v1alpha2
    schema:
      openAPIV3Schema:
        properties:
          apiVersion:
            description: 'APIVersion defines the versioned schema of this representation
              of an object. Servers should convert recognized schemas to the latest
              internal value, and may reject unrecognized values. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#resources'
            type: string
          kind:
            description: 'Kind is a string value representing the REST resource this
              object represents. Servers may infer this from the endpoint the client
              submits requests to. Cannot be updated. In CamelCase. More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#types-kinds'
            type: string
          metadata:
            type: object
          roleRef:
            properties:
              name:
                type: string
              namespace:
                type: string
            required:
            - name
            - namespace
            type: object
          subjects:
            items:
              properties:
                kind:
                  description: Kind of object. Value is "Backend" or "RpcPermission"
                  type: string
                name:
                  description: Name of object.
                  type: string
                namespace:
                  description: Namespace of object. If not set, will be use same namespace.
                  type: string
                permission:
                  description: Permission is the name of permission of backend.
                  type: string
              required:
              - kind
              - name
              type: object
            type: array
        required:
        - roleRef
        - subjects
        type: object
    served: true
    storage: true
status:
  acceptedNames:
    kind: ""
    plural: ""
  conditions: []
  storedVersions: []
`
