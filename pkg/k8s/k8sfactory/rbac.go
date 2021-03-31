package k8sfactory

import (
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
)

func RoleFactory(base *rbacv1.Role, traits ...Trait) *rbacv1.Role {
	var r *rbacv1.Role
	if base == nil {
		r = &rbacv1.Role{}
	} else {
		r = base.DeepCopy()
	}

	if r.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(r)
		if err == nil && !unversioned && len(gvks) > 0 {
			r.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, v := range traits {
		v(r)
	}

	return r
}

func PolicyRule(apiGroups, resources, verbs []string) Trait {
	return func(object interface{}) {
		r, ok := object.(*rbacv1.Role)
		if !ok {
			return
		}

		r.Rules = append(r.Rules, rbacv1.PolicyRule{
			APIGroups: apiGroups,
			Resources: resources,
			Verbs:     verbs,
		})
	}
}

func RoleBindingFactory(base *rbacv1.RoleBinding, traits ...Trait) *rbacv1.RoleBinding {
	var rb *rbacv1.RoleBinding
	if base == nil {
		rb = &rbacv1.RoleBinding{}
	} else {
		rb = base.DeepCopy()
	}

	if rb.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(rb)
		if err == nil && !unversioned && len(gvks) > 0 {
			rb.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, v := range traits {
		v(rb)
	}

	return rb
}

func Role(r *rbacv1.Role) Trait {
	return func(object interface{}) {
		rb, ok := object.(*rbacv1.RoleBinding)
		if !ok {
			return
		}
		rb.RoleRef = rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     r.Name,
		}
	}
}

func Subject(v runtime.Object) Trait {
	return func(object interface{}) {
		rb, ok := object.(*rbacv1.RoleBinding)
		if !ok {
			return
		}

		switch obj := v.(type) {
		case *corev1.ServiceAccount:
			rb.Subjects = append(rb.Subjects, rbacv1.Subject{
				Kind: "ServiceAccount",
				Name: obj.Name,
			})
		}
	}
}
