package metav1

import (
	"go.f110.dev/kubeproto/go/apis/metav1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const GroupName = "cert-manager.io."

var (
	GroupVersion       = metav1.GroupVersion{Group: GroupName, Version: "v1"}
	SchemeBuilder      = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme        = SchemeBuilder.AddToScheme
	SchemaGroupVersion = schema.GroupVersion{Group: GroupName, Version: "v1"}
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemaGroupVersion)
	metav1.AddToGroupVersion(scheme, SchemaGroupVersion)
	return nil
}

type ConditionStatus string

const (
	ConditionStatusTrue    ConditionStatus = "True"
	ConditionStatusFalse   ConditionStatus = "False"
	ConditionStatusUnknown ConditionStatus = "Unknown"
)

type LocalObjectReference struct {
	// Name of the resource being referred to.
	// More info: https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
	Name string `json:"name"`
}

func (in *LocalObjectReference) DeepCopyInto(out *LocalObjectReference) {
	*out = *in
}

func (in *LocalObjectReference) DeepCopy() *LocalObjectReference {
	if in == nil {
		return nil
	}
	out := new(LocalObjectReference)
	in.DeepCopyInto(out)
	return out
}

type ObjectReference struct {
	// Name of the resource being referred to.
	Name string `json:"name"`
	// Kind of the resource being referred to.
	Kind string `json:"kind,omitempty"`
	// Group of the resource being referred to.
	Group string `json:"group,omitempty"`
}

func (in *ObjectReference) DeepCopyInto(out *ObjectReference) {
	*out = *in
}

func (in *ObjectReference) DeepCopy() *ObjectReference {
	if in == nil {
		return nil
	}
	out := new(ObjectReference)
	in.DeepCopyInto(out)
	return out
}

type SecretKeySelector struct {
	// The name of the Secret resource being referred to.
	LocalObjectReference `json:",inline"`
	// The key of the entry in the Secret resource's `data` field to be used.
	// Some instances of this field may be defaulted, in others it may be
	// required.
	Key string `json:"key,omitempty"`
}

func (in *SecretKeySelector) DeepCopyInto(out *SecretKeySelector) {
	*out = *in
	out.LocalObjectReference = in.LocalObjectReference
}

func (in *SecretKeySelector) DeepCopy() *SecretKeySelector {
	if in == nil {
		return nil
	}
	out := new(SecretKeySelector)
	in.DeepCopyInto(out)
	return out
}
