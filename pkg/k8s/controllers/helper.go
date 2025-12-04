package controllers

import (
	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"
)

func resetPod(in *corev1.Pod) *corev1.Pod {
	out := in.DeepCopy()
	out.DeletionTimestamp = nil
	out.CreationTimestamp = &metav1.Time{}
	out.Status = &corev1.PodStatus{}
	return out
}
