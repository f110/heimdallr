package controllers

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"

	"go.f110.dev/heimdallr/pkg/k8s/api/etcd"
	"go.f110.dev/heimdallr/pkg/k8s/api/etcdv1alpha2"
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
		Traits      []k8sfactory.Trait
		Pods        []*corev1.Pod
		ExpectPhase etcdv1alpha2.EtcdClusterPhase
	}{
		{
			Name:        "Doesn't have any pod",
			ExpectPhase: etcdv1alpha2.EtcdClusterPhasePending,
		},
		{
			Name: "One pod created",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase),
			},
			ExpectPhase: etcdv1alpha2.EtcdClusterPhaseInitializing,
		},
		{
			Name: "There are two pods",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
			},
			ExpectPhase: etcdv1alpha2.EtcdClusterPhaseCreating,
		},
		{
			Name: "There are pods more than a majority",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
			},
			Traits:      []k8sfactory.Trait{},
			ExpectPhase: etcdv1alpha2.EtcdClusterPhaseCreating,
		},
		{
			Name: "There are three pods",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
			},
			ExpectPhase: etcdv1alpha2.EtcdClusterPhaseRunning,
		},
		{
			Name: "There are two pods and 3rd pod is creating",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
				k8sfactory.PodFactory(etcdPodBase),
			},
			ExpectPhase: etcdv1alpha2.EtcdClusterPhaseCreating,
		},
		{
			Name: "There are three pods and one pod is not ready",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
				k8sfactory.PodFactory(etcdPodBase),
			},
			Traits:      []k8sfactory.Trait{etcd.Ready},
			ExpectPhase: etcdv1alpha2.EtcdClusterPhaseDegrading,
		},
		{
			Name: "There are two pods and creation completed",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
			},
			Traits:      []k8sfactory.Trait{etcd.Ready, etcd.CreatingCompleted},
			ExpectPhase: etcdv1alpha2.EtcdClusterPhaseDegrading,
		},
		{
			Name: "There is temporary member",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
				k8sfactory.PodFactory(etcdPodBase,
					k8sfactory.Ready,
					k8sfactory.Annotation(etcd.AnnotationKeyTemporaryMember, "yes"),
				),
			},
			Traits:      []k8sfactory.Trait{etcd.Ready, etcd.CreatingCompleted},
			ExpectPhase: etcdv1alpha2.EtcdClusterPhaseUpdating,
		},
		{
			Name: "There are three pods and one pod is failed",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready, k8sfactory.PodFailed),
			},
			Traits:      []k8sfactory.Trait{etcd.Ready, etcd.CreatingCompleted},
			ExpectPhase: etcdv1alpha2.EtcdClusterPhaseDegrading,
		},
		{
			Name: "There are three pods and one pod is not ready, cluster creation is already finished",
			Pods: []*corev1.Pod{
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
				k8sfactory.PodFactory(etcdPodBase, k8sfactory.Ready),
				k8sfactory.PodFactory(etcdPodBase),
			},
			Traits:      []k8sfactory.Trait{etcd.Ready, etcd.CreatingCompleted},
			ExpectPhase: etcdv1alpha2.EtcdClusterPhaseDegrading,
		},
	}

	for _, tt := range cases {
		t.Run(tt.Name, func(t *testing.T) {
			e := etcd.Factory(nil, k8sfactory.Name("test"), etcd.HighAvailability)
			e = etcd.Factory(e, tt.Traits...)
			ec := NewEtcdCluster(e, clusterDomain, logger.Log, nil)
			if len(tt.Pods) > 0 {
				ec.SetOwnedPods(tt.Pods)
			}
			assert.Equal(t, tt.ExpectPhase, ec.CurrentPhase(), tt.Name)
		})
	}
}

func TestEtcdCluster_EqualAnnotation(t *testing.T) {
	cases := []struct {
		Name  string
		Left  map[string]string
		Right map[string]string
		Equal bool
	}{
		{
			Left:  map[string]string{},
			Right: map[string]string{},
			Equal: true,
		},
		{
			Left:  map[string]string{},
			Right: map[string]string{"foo": "bar"},
			Equal: false,
		},
		{
			Left:  map[string]string{"foo": "bar"},
			Right: map[string]string{},
			Equal: false,
		},
		{
			Left:  map[string]string{etcd.AnnotationKeyTemporaryMember: "true"},
			Right: map[string]string{},
			Equal: true,
		},
		{
			Left:  map[string]string{},
			Right: map[string]string{etcd.AnnotationKeyTemporaryMember: "true"},
			Equal: true,
		},
		{
			Left:  map[string]string{etcd.AnnotationKeyServerCertificate: "foo", "foo": "bar"},
			Right: map[string]string{"foo": "bar"},
			Equal: true,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			e := &EtcdCluster{}
			assert.Equal(t, tc.Equal, e.EqualAnnotation(tc.Left, tc.Right))
		})
	}
}

func TestEtcdCluster_EqualLabels(t *testing.T) {
	cases := []struct {
		Name  string
		Left  map[string]string
		Right map[string]string
		Equal bool
	}{
		{
			Left:  map[string]string{},
			Right: map[string]string{},
			Equal: true,
		},
		{
			Left:  map[string]string{},
			Right: map[string]string{"foo": "bar"},
			Equal: false,
		},
		{
			Left:  map[string]string{"foo": "bar"},
			Right: map[string]string{},
			Equal: false,
		},
		{
			Left:  map[string]string{etcd.LabelNameRole: "etcd"},
			Right: map[string]string{},
			Equal: true,
		},
		{
			Left:  map[string]string{},
			Right: map[string]string{etcd.LabelNameEtcdVersion: "foo"},
			Equal: true,
		},
		{
			Left:  map[string]string{etcd.LabelNameEtcdVersion: "foo", "foo": "bar"},
			Right: map[string]string{"foo": "bar"},
			Equal: true,
		},
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			e := &EtcdCluster{}
			assert.Equal(t, tc.Equal, e.EqualLabels(tc.Left, tc.Right))
		})
	}
}

func TestEtcdCluster_MemberPodSpec(t *testing.T) {
	e := etcd.Factory(nil,
		k8sfactory.Name(normalizeName(t.Name())),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.Created,
		etcd.Member(3),
	)
	c := NewEtcdCluster(e, "cluster.local", logger.Log, nil)
	ca, err := c.CA()
	require.NoError(t, err)
	c.SetCASecret(ca)
	serverS, err := c.ServerCertSecret()
	require.NoError(t, err)
	c.SetServerCertSecret(serverS)
	clientS, err := c.ClientCertSecret()
	require.NoError(t, err)
	c.SetClientCertSecret(clientS)

	pod := c.newEtcdPod(defaultEtcdVersion, 1, "existing", nil, false)

	var wipeData, addMember *corev1.Container
	for i, v := range pod.Spec.InitContainers {
		switch v.Name {
		case "wipe-data":
			wipeData = &pod.Spec.InitContainers[i]
		case "add-member":
			addMember = &pod.Spec.InitContainers[i]
		}
	}
	require.NotNil(t, wipeData, "The Pod doesn't have the init container that wipes the data directory")
	require.NotNil(t, addMember, "The Pod doesn't have the init container that manipulates the member")

	script := addMember.Command[2]
	assert.NotContains(t, script, "member update")
	assert.Contains(t, script, "member remove")
	assert.Contains(t, script, "member add")
}
