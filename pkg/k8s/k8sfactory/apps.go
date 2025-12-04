package k8sfactory

import (
	"go.f110.dev/kubeproto/go/apis/appsv1"
	"k8s.io/client-go/kubernetes/scheme"
)

func DeploymentFactory(base *appsv1.Deployment, traits ...Trait) *appsv1.Deployment {
	var d *appsv1.Deployment
	if base == nil {
		d = &appsv1.Deployment{Spec: &appsv1.DeploymentSpec{}, Status: &appsv1.DeploymentStatus{}}
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

func Replicas(v int) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *appsv1.Deployment:
			obj.Spec.Replicas = v
		}
	}
}
