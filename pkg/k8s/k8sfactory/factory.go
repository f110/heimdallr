package k8sfactory

import (
	"math/rand"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

type Trait func(object interface{})

func PodFactory(base *corev1.Pod, traits ...Trait) *corev1.Pod {
	var p *corev1.Pod
	if base == nil {
		p = &corev1.Pod{}
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
		}
	}
}

func PodIsReady(v interface{}) {
	p, ok := v.(*corev1.Pod)
	if !ok {
		return
	}
	if p.GenerateName != "" && p.Name == "" {
		p.Name = p.GenerateName + randomString(5)
	}
	p.CreationTimestamp = metav1.Now()
	p.Status.Phase = corev1.PodRunning
	containerStatus := make([]corev1.ContainerStatus, 0)
	for _, v := range p.Spec.Containers {
		containerStatus = append(containerStatus, corev1.ContainerStatus{
			Name:  v.Name,
			Ready: true,
		})
	}
	p.Status.ContainerStatuses = containerStatus
	p.Status.Conditions = append(p.Status.Conditions, corev1.PodCondition{Type: corev1.PodReady, Status: corev1.ConditionTrue})
}

func PodFailed(v interface{}) {
	p, ok := v.(*corev1.Pod)
	if !ok {
		return
	}
	p.Status.Phase = corev1.PodFailed
}

func Container(c *corev1.Container) Trait {
	return func(v interface{}) {
		p, ok := v.(*corev1.Pod)
		if !ok {
			return
		}
		p.Spec.Containers = append(p.Spec.Containers, *c)
	}
}

func ContainerFactory(base *corev1.Container, traits ...Trait) *corev1.Container {
	var c *corev1.Container
	if base == nil {
		c = &corev1.Container{}
	} else {
		c = base
	}

	for _, v := range traits {
		v(c)
	}

	return c
}

func Image(image string, cmd []string) Trait {
	return func(object interface{}) {
		c, ok := object.(*corev1.Container)
		if !ok {
			return
		}
		c.Image = image
		c.Command = cmd
	}
}

func EnvVar(k, v string) Trait {
	return func(object interface{}) {
		c, ok := object.(*corev1.Container)
		if !ok {
			return
		}
		c.Env = append(c.Env, corev1.EnvVar{
			Name:  k,
			Value: v,
		})
	}
}

var charset = []byte("abcdefghijklmnopqrstuvwxyz0123456789")

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	return string(b)
}
