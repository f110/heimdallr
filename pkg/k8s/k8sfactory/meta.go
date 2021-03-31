package k8sfactory

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func Name(v string) Trait {
	return func(object interface{}) {
		m, ok := object.(metav1.Object)
		if ok {
			m.SetName(v)
			return
		}

		switch obj := object.(type) {
		case *corev1.Container:
			obj.Name = v
		}
	}
}

func Namespace(v string) Trait {
	return func(object interface{}) {
		m, ok := object.(metav1.Object)
		if ok {
			m.SetNamespace(v)
			return
		}
	}
}

func Annotation(k, v string) Trait {
	return func(object interface{}) {
		m, ok := object.(metav1.Object)
		if ok {
			a := m.GetAnnotations()
			if a == nil {
				a = make(map[string]string)
			}
			a[k] = v
			m.SetAnnotations(a)
			return
		}
	}
}

func Label(v ...string) Trait {
	return func(object interface{}) {
		m, ok := object.(metav1.Object)
		if ok {
			a := m.GetLabels()
			if a == nil {
				a = make(map[string]string)
			}
			for i := 0; i < len(v); i += 2 {
				a[v[i]] = v[i+1]
			}
			m.SetLabels(a)
			return
		}
	}
}

func ControlledBy(v runtime.Object, s *runtime.Scheme) Trait {
	return func(object interface{}) {
		m, ok := object.(metav1.Object)
		if ok {
			gvks, _, err := s.ObjectKinds(v)
			if err != nil {
				return
			}
			if len(gvks) == 0 {
				return
			}
			objectMeta, ok := v.(metav1.Object)
			if !ok {
				return
			}

			ref := append(m.GetOwnerReferences(), *metav1.NewControllerRef(objectMeta, gvks[0]))
			m.SetOwnerReferences(ref)
		}
	}
}

func MatchLabel(v map[string]string) *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchLabels: v,
	}
}

func MatchExpression(v ...metav1.LabelSelectorRequirement) *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchExpressions: v,
	}
}
