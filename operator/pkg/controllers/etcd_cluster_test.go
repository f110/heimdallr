package controllers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"

	"go.f110.dev/heimdallr/operator/pkg/api/etcd"
	etcdv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
	"go.f110.dev/heimdallr/pkg/logger"
)

func TestEtcdCluster_CurrentPhase(t *testing.T) {
	const clusterDomain = "cluster.local"
	etcdPodBase := k8sfactory.PodFactory(nil,
		k8sfactory.Container(
			k8sfactory.ContainerFactory(nil, k8sfactory.Name("etcd")),
		),
	)

	cases := []struct {
		Name        string
		Traits      []etcd.Trait
		Pods        []*corev1.Pod
		ExpectPhase etcdv1alpha2.EtcdClusterPhase
	}{
		{
			Name:        "Doesn't have any pod",
			ExpectPhase: etcdv1alpha2.ClusterPhasePending,
		},
		{
			Name: "One pod created",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase),
			},
			ExpectPhase: etcdv1alpha2.ClusterPhaseInitializing,
		},
		{
			Name: "There are two pods",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
			},
			ExpectPhase: etcdv1alpha2.ClusterPhaseCreating,
		},
		{
			Name: "There are pods more than a majority",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
			},
			Traits:      []etcd.Trait{etcd.Ready},
			ExpectPhase: etcdv1alpha2.ClusterPhaseCreating,
		},
		{
			Name: "There are three pods",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
			},
			ExpectPhase: etcdv1alpha2.ClusterPhaseRunning,
		},
		{
			Name: "There are two pods and 3rd pod is creating",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
				k8sfactory.PodFactory(etcdPodBase),
			},
			ExpectPhase: etcdv1alpha2.ClusterPhaseCreating,
		},
		{
			Name: "There are three pods and one pod is not ready",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
				k8sfactory.PodFactory(etcdPodBase),
			},
			Traits:      []etcd.Trait{etcd.Ready},
			ExpectPhase: etcdv1alpha2.ClusterPhaseCreating,
		},
		{
			Name: "There are two pods and creation completed",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
			},
			Traits:      []etcd.Trait{etcd.Ready, etcd.CreatingCompleted},
			ExpectPhase: etcdv1alpha2.ClusterPhaseDegrading,
		},
		{
			Name: "There is temporary member",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
				k8sfactory.PodFactory(etcdPodBase,
					k8sfactory.PodIsReady,
					k8sfactory.Annotation(etcd.AnnotationKeyTemporaryMember, "yes"),
				),
			},
			Traits:      []etcd.Trait{etcd.Ready, etcd.CreatingCompleted},
			ExpectPhase: etcdv1alpha2.ClusterPhaseUpdating,
		},
		{
			Name: "There are three pods and one pod is failed",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady, k8sfactory.PodFailed),
			},
			Traits:      []etcd.Trait{etcd.Ready, etcd.CreatingCompleted},
			ExpectPhase: etcdv1alpha2.ClusterPhaseDegrading,
		},
		{
			Name: "There are three pods and one pod is not ready, cluster creation is already finished",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.PodIsReady),
				k8sfactory.PodFactory(etcdPodBase),
			},
			Traits:      []etcd.Trait{etcd.Ready, etcd.CreatingCompleted},
			ExpectPhase: etcdv1alpha2.ClusterPhaseDegrading,
		},
	}

	for _, tt := range cases {
		e := etcd.Factory(nil, etcd.Name("test"), etcd.HighAvailability)
		e = etcd.Factory(e, tt.Traits...)
		ec := NewEtcdCluster(e, clusterDomain, logger.Log, nil)
		if len(tt.Pods) > 0 {
			ec.SetOwnedPods(tt.Pods)
		}
		assert.Equal(t, tt.ExpectPhase, ec.CurrentPhase(), tt.Name)
	}
}
