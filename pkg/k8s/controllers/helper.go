package controllers

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func resetPod(in *corev1.Pod) *corev1.Pod {
	out := in.DeepCopy()
	out.SetDeletionTimestamp(nil)
	out.SetCreationTimestamp(metav1.Time{})
	out.Status = corev1.PodStatus{}
	return out
}
