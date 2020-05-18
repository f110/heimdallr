package controllers

import (
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/diff"

	etcdv1alpha1 "github.com/f110/lagrangian-proxy/operator/pkg/api/etcd/v1alpha1"
)

func EqualSecret(actual, expect *corev1.Secret) (bool, []string) {
	actual = actual.DeepCopy()
	expect = expect.DeepCopy()

	expect.ObjectMeta.SetOwnerReferences([]metav1.OwnerReference{})
	actual.ObjectMeta.SetOwnerReferences([]metav1.OwnerReference{})

	if !reflect.DeepEqual(expect.ObjectMeta, actual.ObjectMeta) {
		return false, []string{diff.ObjectGoPrintSideBySide(expect.ObjectMeta, actual.ObjectMeta)}
	}

	msg := make([]string, 0)
	for k := range expect.Data {
		if _, ok := actual.Data[k]; !ok {
			msg = append(msg, fmt.Sprintf("wrong object: expect %s but not have", k))
		}
	}
	for k := range actual.Data {
		if _, ok := expect.Data[k]; !ok {
			msg = append(msg, fmt.Sprintf("wrong object: unexpected key %s", k))
		}
	}

	return len(msg) == 0, msg
}

func EqualEtcdCluster(actual, expect *etcdv1alpha1.EtcdCluster) (bool, string) {
	actual = actual.DeepCopy()
	expect = expect.DeepCopy()
	if !reflect.DeepEqual(expect.Spec, actual.Spec) {
		return false, diff.ObjectGoPrintSideBySide(expect.Spec, actual.Spec)
	}

	return true, ""
}
