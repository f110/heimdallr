package controllers

import (
	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"
)

// FieldManager is the name of the field manager of the operator.
// The operator uses it as the User-Agent too, so that the fields updated by Update are recorded with the same name.
const FieldManager = "heimdallr-operator"

var applyOptions = metav1.ApplyOptions{FieldManager: FieldManager, Force: true}

func resetPod(in *corev1.Pod) *corev1.Pod {
	out := in.DeepCopy()
	out.DeletionTimestamp = nil
	out.CreationTimestamp = &metav1.Time{}
	out.Status = &corev1.PodStatus{}
	return out
}
