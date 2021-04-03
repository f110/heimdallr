package k8sfactory

import (
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/scheme"
)

func PodDisruptionBudgetFactory(base *policyv1beta1.PodDisruptionBudget, traits ...Trait) *policyv1beta1.PodDisruptionBudget {
	var p *policyv1beta1.PodDisruptionBudget
	if base == nil {
		p = &policyv1beta1.PodDisruptionBudget{}
	} else {
		p = base.DeepCopy()
	}

	if p.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(p)
		if err == nil && !unversioned && len(gvks) > 0 {
			p.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, v := range traits {
		v(p)
	}

	return p
}

func MinAvailable(v int) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *policyv1beta1.PodDisruptionBudget:
			m := intstr.FromInt(v)
			obj.Spec.MinAvailable = &m
		}
	}
}
