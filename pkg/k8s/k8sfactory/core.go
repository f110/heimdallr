package k8sfactory

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/pointer"
)

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

func Ready(v interface{}) {
	p, ok := v.(*corev1.Pod)
	if !ok {
		return
	}
	p.Status.Phase = corev1.PodRunning
	containerStatus := make([]corev1.ContainerStatus, 0)
	for _, v := range p.Spec.Containers {
		containerStatus = append(containerStatus, corev1.ContainerStatus{
			Name:    v.Name,
			Ready:   true,
			Image:   v.Image,
			Started: pointer.BoolPtr(true),
		})
	}
	p.Status.ContainerStatuses = containerStatus
	p.Status.Conditions = append(p.Status.Conditions, corev1.PodCondition{
		Type:               corev1.PodReady,
		Status:             corev1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
	})
}

// NotReady is the trait function for k8sfactory.
// The object is created but not ready.
func NotReady(v interface{}) {
	p, ok := v.(*corev1.Pod)
	if !ok {
		return
	}

	p.Status.Phase = corev1.PodRunning
	p.Status.Conditions = append(p.Status.Conditions, corev1.PodCondition{
		Type:               corev1.PodReady,
		Status:             corev1.ConditionFalse,
		LastTransitionTime: metav1.Now(),
	})
	containerStatus := make([]corev1.ContainerStatus, 0)
	for _, v := range p.Spec.Containers {
		containerStatus = append(containerStatus, corev1.ContainerStatus{
			Name:    v.Name,
			Image:   v.Image,
			Ready:   false,
			Started: pointer.BoolPtr(true),
		})
	}
	p.Status.ContainerStatuses = containerStatus
}

func PodSucceeded(v interface{}) {
	p, ok := v.(*corev1.Pod)
	if !ok {
		return
	}
	p.Status.Phase = corev1.PodSucceeded
}

func PodFailed(v interface{}) {
	p, ok := v.(*corev1.Pod)
	if !ok {
		return
	}
	p.Status.Phase = corev1.PodFailed
}

func RestartPolicy(policy corev1.RestartPolicy) Trait {
	return func(object interface{}) {
		p, ok := object.(*corev1.Pod)
		if !ok {
			return
		}
		p.Spec.RestartPolicy = policy
	}
}

func Container(c *corev1.Container) Trait {
	return func(object interface{}) {
		p, ok := object.(*corev1.Pod)
		if !ok {
			return
		}
		p.Spec.Containers = append(p.Spec.Containers, *c)
	}
}

func InitContainer(c *corev1.Container) Trait {
	return func(object interface{}) {
		if c == nil {
			return
		}

		switch obj := object.(type) {
		case *corev1.Pod:
			obj.Spec.InitContainers = append(obj.Spec.InitContainers, *c)
		}
	}
}

func PreferredInterPodAntiAffinity(weight int32, selector *metav1.LabelSelector, key string) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *corev1.Pod:
			if obj.Spec.Affinity == nil {
				obj.Spec.Affinity = &corev1.Affinity{}
			}
			if obj.Spec.Affinity.PodAntiAffinity == nil {
				obj.Spec.Affinity.PodAntiAffinity = &corev1.PodAntiAffinity{}
			}

			obj.Spec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution = append(
				obj.Spec.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution,
				corev1.WeightedPodAffinityTerm{
					Weight: weight,
					PodAffinityTerm: corev1.PodAffinityTerm{
						LabelSelector: selector,
						TopologyKey:   key,
					},
				},
			)
		}
	}
}

func ServiceAccount(v string) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *corev1.Pod:
			obj.Spec.ServiceAccountName = v
		}
	}
}

func Subdomain(v string) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *corev1.Pod:
			obj.Spec.Subdomain = v
		}
	}
}

func ShareProcessNamespace(object any) {
	switch obj := object.(type) {
	case *corev1.Pod:
		obj.Spec.ShareProcessNamespace = pointer.Bool(true)
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

func Args(args ...string) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *corev1.Container:
			obj.Args = args
		}
	}
}

func PullPolicy(p corev1.PullPolicy) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *corev1.Container:
			obj.ImagePullPolicy = p
		}
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

func EnvFromField(k, v string) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *corev1.Container:
			obj.Env = append(obj.Env, corev1.EnvVar{
				Name: k,
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: v,
					},
				},
			})
		}
	}
}

func LivenessProbe(p *corev1.Probe) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *corev1.Container:
			obj.LivenessProbe = p
		}
	}
}

func ReadinessProbe(p *corev1.Probe) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *corev1.Container:
			obj.ReadinessProbe = p
		}
	}
}

func TCPProbe(port int) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			TCPSocket: &corev1.TCPSocketAction{
				Port: intstr.FromInt(port),
			},
		},
	}
}

func HTTPProbe(port int, path string) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Port: intstr.FromInt(port),
				Path: path,
			},
		},
	}
}

func ExecProbe(command ...string) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			Exec: &corev1.ExecAction{Command: command},
		},
	}
}

func GRPCProbe(port int) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			GRPC: &corev1.GRPCAction{
				Port: int32(port),
			},
		},
	}
}

func Volume(vol *VolumeSource) Trait {
	return func(object interface{}) {
		if vol == nil {
			return
		}

		switch obj := object.(type) {
		case *corev1.Container:
			obj.VolumeMounts = append(obj.VolumeMounts, vol.Mount)
		case *corev1.Pod:
			obj.Spec.Volumes = append(obj.Spec.Volumes, vol.Source)
		}
	}
}

func ServiceAccountFactory(base *corev1.ServiceAccount, traits ...Trait) *corev1.ServiceAccount {
	var sa *corev1.ServiceAccount
	if base == nil {
		sa = &corev1.ServiceAccount{}
	} else {
		sa = base.DeepCopy()
	}

	if sa.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(sa)
		if err == nil && !unversioned && len(gvks) > 0 {
			sa.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, v := range traits {
		v(sa)
	}

	return sa
}

func ServiceFactory(base *corev1.Service, traits ...Trait) *corev1.Service {
	var s *corev1.Service
	if base == nil {
		s = &corev1.Service{}
	} else {
		s = base.DeepCopy()
	}

	if s.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(s)
		if err == nil && !unversioned && len(gvks) > 0 {
			s.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, v := range traits {
		v(s)
	}

	return s
}

func ClusterIP(object interface{}) {
	switch obj := object.(type) {
	case *corev1.Service:
		obj.Spec.Type = corev1.ServiceTypeClusterIP
	}
}

func LoadBalancer(object interface{}) {
	switch obj := object.(type) {
	case *corev1.Service:
		obj.Spec.Type = corev1.ServiceTypeLoadBalancer
	}
}

func LoadBalancerIP(ip string) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *corev1.Service:
			obj.Spec.LoadBalancerIP = ip
		}
	}
}

func TrafficPolicyLocal(object interface{}) {
	switch obj := object.(type) {
	case *corev1.Service:
		obj.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeLocal
	}
}

func IPNone(object interface{}) {
	switch obj := object.(type) {
	case *corev1.Service:
		obj.Spec.ClusterIP = corev1.ClusterIPNone
	}
}

func Selector(v ...string) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *corev1.Service:
			sel := make(map[string]string)
			for i := 0; i < len(v); i += 2 {
				sel[v[i]] = v[i+1]
			}
			obj.Spec.Selector = sel
		}
	}
}

func Port(name string, protocol corev1.Protocol, port int32) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *corev1.Service:
			obj.Spec.Ports = append(obj.Spec.Ports, corev1.ServicePort{
				Name:     name,
				Protocol: protocol,
				Port:     port,
			})
		case *corev1.Container:
			obj.Ports = append(obj.Ports, corev1.ContainerPort{
				Name:          name,
				Protocol:      protocol,
				ContainerPort: port,
			})
		}
	}
}

func TargetPort(name string, protocol corev1.Protocol, port int32, targetPort intstr.IntOrString) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *corev1.Service:
			obj.Spec.Ports = append(obj.Spec.Ports, corev1.ServicePort{
				Name:       name,
				Protocol:   protocol,
				Port:       port,
				TargetPort: targetPort,
			})
		}
	}
}

func SecretFactory(base *corev1.Secret, traits ...Trait) *corev1.Secret {
	var s *corev1.Secret
	if base == nil {
		s = &corev1.Secret{}
	} else {
		s = base.DeepCopy()
	}

	if s.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(s)
		if err == nil && !unversioned && len(gvks) > 0 {
			s.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, v := range traits {
		v(s)
	}

	return s
}

func Data(key string, value []byte) Trait {
	return func(v interface{}) {
		switch obj := v.(type) {
		case *corev1.Secret:
			if obj.Data == nil {
				obj.Data = make(map[string][]byte)
			}
			obj.Data[key] = value
		case *corev1.ConfigMap:
			if obj.Data == nil {
				obj.Data = make(map[string]string)
			}
			obj.Data[key] = string(value)
		}
	}
}

func ConfigMapFactory(base *corev1.ConfigMap, traits ...Trait) *corev1.ConfigMap {
	var cm *corev1.ConfigMap
	if base == nil {
		cm = &corev1.ConfigMap{}
	} else {
		cm = base.DeepCopy()
	}

	if cm.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(cm)
		if err == nil && !unversioned && len(gvks) > 0 {
			cm.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, v := range traits {
		v(cm)
	}

	return cm
}

func Requests(req corev1.ResourceList) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *corev1.Container:
			obj.Resources.Requests = req
		}
	}
}

func Limits(lim corev1.ResourceList) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *corev1.Container:
			obj.Resources.Limits = lim
		}
	}
}

func EventFactory(base *corev1.Event, traits ...Trait) *corev1.Event {
	var e *corev1.Event
	if base == nil {
		e = &corev1.Event{}
	} else {
		e = base.DeepCopy()
	}

	if e.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(e)
		if err == nil && !unversioned && len(gvks) > 0 {
			e.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, v := range traits {
		v(e)
	}

	return e
}

func Reason(v string) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *corev1.Event:
			obj.Reason = v
		}
	}
}
