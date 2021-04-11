package k8sfactory

import (
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/uuid"
)

func Name(v string) Trait {
	return func(object interface{}) {
		m, ok := object.(interface {
			SetName(string)
		})
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

func Namef(format string, a ...interface{}) Trait {
	return Name(fmt.Sprintf(format, a...))
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

func UID() Trait {
	return func(object interface{}) {
		m, ok := object.(metav1.Object)
		if ok {
			m.SetUID(uuid.NewUUID())
		}
	}
}

func Created(object interface{}) {
	m, ok := object.(metav1.Object)
	if ok {
		m.SetCreationTimestamp(metav1.Now())
	}
}

func Delete(object interface{}) {
	m, ok := object.(metav1.Object)
	if ok {
		n := metav1.Now()
		m.SetDeletionTimestamp(&n)
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

func LabelMap(label map[string]string) Trait {
	return func(object interface{}) {
		m, ok := object.(metav1.Object)
		if ok {
			m.SetLabels(label)
			return
		}
	}
}

func ControlledBy(v runtime.Object, s *runtime.Scheme) Trait {
	return func(object interface{}) {
		owner, ok := v.(metav1.Object)
		if !ok {
			return
		}

		m, ok := object.(metav1.Object)
		if ok {
			if metav1.IsControlledBy(m, owner) {
				return
			}

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

func MatchLabelSelector(label map[string]string) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *corev1.Service:
			obj.Spec.Selector = label
		case *appsv1.Deployment:
			obj.Spec.Selector = &metav1.LabelSelector{MatchLabels: label}
		case *policyv1beta1.PodDisruptionBudget:
			obj.Spec.Selector = &metav1.LabelSelector{MatchLabels: label}
		}
	}
}

func Finalizer(v string) Trait {
	return func(object interface{}) {
		m, ok := object.(metav1.Object)
		if ok {
			found := false
			for _, f := range m.GetFinalizers() {
				if f == v {
					found = true
					break
				}
			}
			if found {
				return
			}

			m.SetFinalizers(append(m.GetFinalizers(), v))
		}
	}
}
