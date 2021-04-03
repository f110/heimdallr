package k8sfactory

import (
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

func DeploymentFactory(base *appsv1.Deployment, traits ...Trait) *appsv1.Deployment {
	var d *appsv1.Deployment
	if base == nil {
		d = &appsv1.Deployment{}
	} else {
		d = base.DeepCopy()
	}

	if d.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(d)
		if err == nil && !unversioned && len(gvks) > 0 {
			d.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, v := range traits {
		v(d)
	}

	return d
}

func Replicas(v int32) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *appsv1.Deployment:
			obj.Spec.Replicas = &v
		}
	}
}
