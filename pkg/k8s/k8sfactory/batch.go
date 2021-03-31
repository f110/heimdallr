package k8sfactory

import (
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

func CronJobFactory(base *batchv1beta1.CronJob, traits ...Trait) *batchv1beta1.CronJob {
	var cj *batchv1beta1.CronJob
	if base == nil {
		cj = &batchv1beta1.CronJob{}
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
		cj, ok := object.(*batchv1beta1.CronJob)
		if !ok {
			return
		}
		cj.Spec.Schedule = v
	}
}

func Job(j *batchv1.Job) Trait {
	return func(object interface{}) {
		switch obj := object.(type) {
		case *batchv1beta1.CronJob:
			obj.Spec.JobTemplate = batchv1beta1.JobTemplateSpec{
				ObjectMeta: j.ObjectMeta,
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
				ObjectMeta: p.ObjectMeta,
				Spec:       p.Spec,
			}
		}
	}
}
