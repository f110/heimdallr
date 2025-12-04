package k8sfactory

import (
	"fmt"
	"time"

	"go.f110.dev/kubeproto/go/apis/appsv1"
	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"
	"go.f110.dev/kubeproto/go/apis/policyv1"
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
		objMeta, ok := object.(metav1.Object)
		if ok {
			objMeta.GetObjectMeta().Name = v
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
			m.GetObjectMeta().Namespace = v
			return
		}
	}
}

func UID() Trait {
	return func(object interface{}) {
		m, ok := object.(metav1.Object)
		if ok {
			m.GetObjectMeta().UID = string(uuid.NewUUID())
		}
	}
}

func Created(object interface{}) {
	m, ok := object.(metav1.Object)
	if ok {
		now := metav1.Now()
		m.GetObjectMeta().CreationTimestamp = &now
		m.GetObjectMeta().UID = string(uuid.NewUUID())
		if m.GetObjectMeta().GenerateName != "" && m.GetObjectMeta().Name == "" {
			m.GetObjectMeta().Name = m.GetObjectMeta().GenerateName + randomString(5)
		}
	}
}

func CreatedAt(now time.Time) Trait {
	return func(object interface{}) {
		Created(object)
		m, ok := object.(metav1.Object)
		if ok {
			t := metav1.NewTime(now)
			m.GetObjectMeta().CreationTimestamp = &t
		}
	}
}

func Delete(object interface{}) {
	m, ok := object.(metav1.Object)
	if ok {
		n := metav1.Now()
		m.GetObjectMeta().DeletionTimestamp = &n
	}
}

func Annotation(k, v string) Trait {
	return func(object interface{}) {
		m, ok := object.(metav1.Object)
		if ok {
			a := m.GetObjectMeta().Annotations
			if a == nil {
				a = make(map[string]string)
			}
			if v == "" {
				delete(a, k)
			} else {
				a[k] = v
			}
			m.GetObjectMeta().Annotations = a
			return
		}
	}
}

func Annotations(annotations map[string]string) Trait {
	return func(object interface{}) {
		m, ok := object.(metav1.Object)
		if ok {
			a := m.GetObjectMeta().Annotations
			if a != nil {
				for k, v := range annotations {
					a[k] = v
				}
			} else {
				a = annotations
			}
			m.GetObjectMeta().Annotations = a
			return
		}
	}
}

func Label(v ...string) Trait {
	return func(object interface{}) {
		m, ok := object.(metav1.Object)
		if ok {
			a := m.GetObjectMeta().Labels
			if a == nil {
				a = make(map[string]string)
			}
			for i := 0; i < len(v); i += 2 {
				a[v[i]] = v[i+1]
			}
			m.GetObjectMeta().Labels = a
			return
		}
	}
}

func Labels(label map[string]string) Trait {
	return func(object interface{}) {
		m, ok := object.(metav1.Object)
		if ok {
			a := m.GetObjectMeta().Labels
			if a != nil {
				for k, v := range label {
					a[k] = v
				}
			} else {
				a = label
			}
			m.GetObjectMeta().Labels = a
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

			ref := append(m.GetObjectMeta().OwnerReferences, metav1.NewControllerRef(*objectMeta.GetObjectMeta(), gvks[0]))
			m.GetObjectMeta().OwnerReferences = ref
		}
	}
}

func ClearOwnerReference(object interface{}) {
	objMeta, ok := object.(metav1.Object)
	if !ok {
		return
	}
	objMeta.GetObjectMeta().OwnerReferences = make([]metav1.OwnerReference, 0)
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
		case *policyv1.PodDisruptionBudget:
			obj.Spec.Selector = &metav1.LabelSelector{MatchLabels: label}
		}
	}
}

func Finalizer(v string) Trait {
	return func(object interface{}) {
		m, ok := object.(metav1.Object)
		if ok {
			found := false
			for _, f := range m.GetObjectMeta().Finalizers {
				if f == v {
					found = true
					break
				}
			}
			if found {
				return
			}

			m.GetObjectMeta().Finalizers = append(m.GetObjectMeta().Finalizers, v)
		}
	}
}
