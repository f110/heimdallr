package k8sfactory

import (
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

func IngressClassFactory(base *networkingv1.IngressClass, traits ...Trait) *networkingv1.IngressClass {
	var ic *networkingv1.IngressClass
	if base == nil {
		ic = &networkingv1.IngressClass{}
	} else {
		ic = base.DeepCopy()
	}

	if ic.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(ic)
		if err == nil && !unversioned && len(gvks) > 0 {
			ic.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, v := range traits {
		v(ic)
	}

	return ic
}

func Controller(v string) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *networkingv1.IngressClass:
			obj.Spec.Controller = v
		}
	}
}

func IngressFactory(base *networkingv1.Ingress, traits ...Trait) *networkingv1.Ingress {
	var ing *networkingv1.Ingress
	if base == nil {
		ing = &networkingv1.Ingress{}
	} else {
		ing = base.DeepCopy()
	}

	if ing.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(ing)
		if err == nil && !unversioned && len(gvks) > 0 {
			ing.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, v := range traits {
		v(ing)
	}

	return ing
}

func IngressClass(v *networkingv1.IngressClass) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *networkingv1.Ingress:
			obj.Spec.IngressClassName = &v.Name
		}
	}
}

func Rule(rule *networkingv1.IngressRule) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *networkingv1.Ingress:
			obj.Spec.Rules = append(obj.Spec.Rules, *rule)
		}
	}
}

func IngressRuleFactory(base *networkingv1.IngressRule, traits ...Trait) *networkingv1.IngressRule {
	var rule *networkingv1.IngressRule
	if base == nil {
		rule = &networkingv1.IngressRule{}
	} else {
		rule = base.DeepCopy()
	}

	for _, v := range traits {
		v(rule)
	}

	return rule
}

func Host(v string) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *networkingv1.IngressRule:
			obj.Host = v
		}
	}
}

func IngressPathFactory(base *networkingv1.HTTPIngressPath, traits ...Trait) *networkingv1.HTTPIngressPath {
	var p *networkingv1.HTTPIngressPath
	if base == nil {
		p = &networkingv1.HTTPIngressPath{}
	} else {
		p = base.DeepCopy()
	}

	for _, v := range traits {
		v(p)
	}

	return p
}

func Path(path string, pt networkingv1.PathType, svc *corev1.Service, port string) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *networkingv1.IngressRule:
			if obj.IngressRuleValue.HTTP == nil {
				obj.IngressRuleValue.HTTP = &networkingv1.HTTPIngressRuleValue{}
			}
			obj.IngressRuleValue.HTTP.Paths = append(obj.IngressRuleValue.HTTP.Paths,
				networkingv1.HTTPIngressPath{
					Path:     path,
					PathType: &pt,
					Backend: networkingv1.IngressBackend{
						Service: &networkingv1.IngressServiceBackend{
							Name: svc.Name,
							Port: networkingv1.ServiceBackendPort{
								Name: port,
							},
						},
					},
				},
			)
		}
	}
}
