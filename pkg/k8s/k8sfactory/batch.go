package k8sfactory

import (
	"go.f110.dev/kubeproto/go/apis/appsv1"
	"go.f110.dev/kubeproto/go/apis/batchv1"
	"go.f110.dev/kubeproto/go/apis/corev1"
	"k8s.io/client-go/kubernetes/scheme"
)

func CronJobFactory(base *batchv1.CronJob, traits ...Trait) *batchv1.CronJob {
	var cj *batchv1.CronJob
	if base == nil {
		cj = &batchv1.CronJob{}
	} else {
		cj = base.DeepCopy()
	}

	if cj.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(cj)
		if err == nil && !unversioned && len(gvks) > 0 {
			cj.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, v := range traits {
		v(cj)
	}

	return cj
}

func Schedule(v string) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *batchv1.CronJob:
			obj.Spec.Schedule = v
		}
	}
}

func Job(j *batchv1.Job) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *batchv1.CronJob:
			obj.Spec.JobTemplate = batchv1.JobTemplateSpec{
				ObjectMeta: &j.ObjectMeta,
				Spec:       j.Spec,
			}
		}
	}
}

func JobFactory(base *batchv1.Job, traits ...Trait) *batchv1.Job {
	var j *batchv1.Job
	if base == nil {
		j = &batchv1.Job{}
	} else {
		j = base.DeepCopy()
	}

	if j.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(j)
		if err == nil && !unversioned && len(gvks) > 0 {
			j.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, v := range traits {
		v(j)
	}

	return j
}

func Pod(p *corev1.Pod) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *batchv1.Job:
			obj.Spec.Template = corev1.PodTemplateSpec{
				ObjectMeta: &p.ObjectMeta,
				Spec:       p.Spec,
			}
		case *appsv1.Deployment:
			obj.Spec.Template = corev1.PodTemplateSpec{
				ObjectMeta: &p.ObjectMeta,
				Spec:       p.Spec,
			}
		}
	}
}
