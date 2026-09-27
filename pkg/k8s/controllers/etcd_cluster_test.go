package controllers

import (
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"

	"go.f110.dev/heimdallr/pkg/cert"
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
	cases := []struct {
		Version string
		Flag    string
	}{
		{Version: "v3.4.3", Flag: "--experimental-peer-skip-client-san-verification"},
		{Version: "v3.5.1", Flag: "--experimental-peer-skip-client-san-verification"},
		{Version: "v3.6.15", Flag: "--peer-skip-client-san-verification"},
	}

	for _, tc := range cases {
		t.Run(tc.Version, func(t *testing.T) {
			c := newTestEtcdCluster(t)
			pod := c.newEtcdPod(tc.Version, 1, "existing", nil, false)

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

			assert.False(t, pod.Spec.ShareProcessNamespace)
			assert.Equal(t, pod.Name, pod.Spec.Hostname)
			assert.Equal(t, c.ServerDiscoveryServiceName(), pod.Spec.Subdomain)
			for _, v := range pod.Spec.Containers {
				assert.NotEqual(t, "sidecar", v.Name)
			}
			for _, v := range pod.Spec.Volumes {
				assert.NotContains(t, []string{"share", "run"}, v.Name)
			}

			var etcdContainer *corev1.Container
			for i, v := range pod.Spec.Containers {
				if v.Name == "etcd" {
					etcdContainer = &pod.Spec.Containers[i]
				}
			}
			require.NotNil(t, etcdContainer)
			script = etcdContainer.Args[1]
			assert.Contains(t, script, "exec /usr/local/bin/etcd ")
			assert.Contains(t, script, " "+tc.Flag)
			assert.NotContains(t, script, "resolv.conf")
			assert.NotContains(t, script, "/var/run/sidecar")
			assert.NotContains(t, script, "/var/run/etcd")
			for _, v := range etcdContainer.VolumeMounts {
				assert.NotContains(t, []string{"share", "run"}, v.Name)
			}
		})
	}
}

func TestEtcdCluster_ShouldUpdate(t *testing.T) {
	t.Run("Same spec", func(t *testing.T) {
		c := newTestEtcdCluster(t)
		pod := k8sfactory.PodFactory(c.newEtcdPod(defaultEtcdVersion, 1, "new", nil, false), k8sfactory.Created)
		assert.False(t, c.ShouldUpdate(pod))

		pod = k8sfactory.PodFactory(
			c.newEtcdPod(defaultEtcdVersion, 2, "existing", []string{"test-1=https://10-0-0-1.default.pod.cluster.local:2380"}, false),
			k8sfactory.Created,
		)
		assert.False(t, c.ShouldUpdate(pod))
	})

	t.Run("Don't have the hash of the spec", func(t *testing.T) {
		c := newTestEtcdCluster(t)
		pod := k8sfactory.PodFactory(c.newEtcdPod(defaultEtcdVersion, 1, "new", nil, false), k8sfactory.Created)
		delete(pod.Annotations, etcd.AnnotationKeyPodSpecHash)
		assert.True(t, c.ShouldUpdate(pod))
	})

	t.Run("Spec is changed", func(t *testing.T) {
		c := newTestEtcdCluster(t)
		pod := k8sfactory.PodFactory(c.newEtcdPod(defaultEtcdVersion, 1, "new", nil, false), k8sfactory.Created)
		c.Spec.AntiAffinity = !c.Spec.AntiAffinity
		assert.True(t, c.ShouldUpdate(pod))
	})
}

func TestEtcdCluster_DNSNames(t *testing.T) {
	c := newTestEtcdCluster(t)

	dnsNames := c.DNSNames()
	assert.Contains(t, dnsNames, fmt.Sprintf("*.%s-discovery.%s.svc.cluster.local", c.Name, c.Namespace))
	assert.Contains(t, dnsNames, fmt.Sprintf("*.%s.pod.cluster.local", c.Namespace))
}

func TestEtcdCluster_ShouldUpdateServerCertificate(t *testing.T) {
	c := newTestEtcdCluster(t)
	caPair, err := c.parseCASecret(c.caSecret)
	require.NoError(t, err)

	t.Run("Up to date", func(t *testing.T) {
		serverCert, _, err := cert.GenerateMutualTLSCertificate(caPair.Cert, caPair.PrivateKey, c.DNSNames(), []string{"127.0.0.1"})
		require.NoError(t, err)

		assert.False(t, c.ShouldUpdateServerCertificate(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})))
	})

	t.Run("Doesn't have the SAN for the discovery service", func(t *testing.T) {
		dnsNames := []string{
			fmt.Sprintf("%s-discovery.%s.svc.cluster.local", c.Name, c.Namespace),
			fmt.Sprintf("%s-client.%s.svc.cluster.local", c.Name, c.Namespace),
			fmt.Sprintf("%s-client.%s.svc", c.Name, c.Namespace),
			fmt.Sprintf("*.%s.pod.cluster.local", c.Namespace),
		}
		serverCert, _, err := cert.GenerateMutualTLSCertificate(caPair.Cert, caPair.PrivateKey, dnsNames, []string{"127.0.0.1"})
		require.NoError(t, err)

		assert.True(t, c.ShouldUpdateServerCertificate(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})))
	})
}

func TestEtcdCluster_DiscoveryService(t *testing.T) {
	c := newTestEtcdCluster(t)

	svc := c.DiscoveryService()
	assert.Equal(t, "None", svc.Spec.ClusterIP)
	assert.True(t, svc.Spec.PublishNotReadyAddresses)
}

func newTestEtcdCluster(t *testing.T) *EtcdCluster {
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

	return c
}
