package controllers

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.etcd.io/etcd/v3/clientv3"
	"go.etcd.io/etcd/v3/etcdserver/etcdserverpb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/f110/lagrangian-proxy/operator/pkg/api/etcd"
	etcdv1alpha1 "github.com/f110/lagrangian-proxy/operator/pkg/api/etcd/v1alpha1"
)

func TestEtcdController(t *testing.T) {
	t.Run("CreatingFirstMember", func(t *testing.T) {
		t.Parallel()

		// In this case, we don't need mocking etcd client.
		f := newEtcdControllerTestRunner(t, nil)

		e := etcdControllerFixtures(t)
		f.RegisterEtcdClusterFixture(e)

		// Setup
		f.ExpectUpdateEtcdCluster()
		f.ExpectCreateSecret()
		f.ExpectCreateSecret()
		f.ExpectCreateSecret()
		// Create first node
		f.ExpectCreatePod()
		f.ExpectCreateService()
		f.ExpectCreateService()
		f.ExpectUpdateEtcdCluster()
		f.Run(t, e)

		member, err := f.coreClient.CoreV1().Pods(e.Namespace).Get(fmt.Sprintf("%s-1", e.Name), metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}

		assert.Contains(t, member.Spec.Containers[0].Command, "--initial-cluster-state=new")
	})

	t.Run("CreatingMember", func(t *testing.T) {
		t.Parallel()

		etcdMockCluster := NewMockCluster()
		etcdMockMaintenance := NewMockMaintenance()
		f := newEtcdControllerTestRunner(t, &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance})

		e := etcdControllerFixtures(t)
		e.Status.Phase = etcdv1alpha1.ClusterPhaseCreating
		f.RegisterEtcdClusterFixture(e)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, nil)
		cluster.registerFundamentalObjectOfEtcdCluster(f)
		member := cluster.AllMembers()[0]
		podIsReady(member)
		f.RegisterPodFixture(member)

		f.ExpectCreatePod()
		f.ExpectUpdateEtcdCluster()
		f.Run(t, e)

		member, err := f.coreClient.CoreV1().Pods(e.Namespace).Get(fmt.Sprintf("%s-2", e.Name), metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		assert.Contains(t, member.Spec.Containers[0].Command, "--initial-cluster-state=existing")
	})

	t.Run("PreparingUpdate", func(t *testing.T) {
		t.Parallel()

		etcdMockCluster := NewMockCluster()
		etcdMockMaintenance := NewMockMaintenance()
		f := newEtcdControllerTestRunner(t, &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance})

		e := etcdControllerFixtures(t)
		e.Status.Phase = etcdv1alpha1.ClusterPhaseRunning
		f.RegisterEtcdClusterFixture(e)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, nil)
		cluster.registerFundamentalObjectOfEtcdCluster(f)
		for _, v := range cluster.AllMembers() {
			podIsReady(v)
			f.RegisterPodFixture(v)
		}
		e.Spec.Version = "v3.3.0"

		f.ExpectCreatePod()
		f.ExpectUpdateEtcdCluster()
		f.Run(t, e)

		member, err := f.coreClient.CoreV1().Pods(e.Namespace).Get(fmt.Sprintf("%s-4", e.Name), metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		assert.Contains(t, member.Spec.Containers[0].Command, "--initial-cluster-state=existing")
		assert.Contains(t, member.Annotations, etcd.AnnotationKeyTemporaryMember)
	})

	t.Run("UpdatingMember", func(t *testing.T) {
		t.Parallel()

		t.Run("DeleteMember", func(t *testing.T) {
			t.Parallel()

			etcdMockCluster := NewMockCluster()
			etcdMockMaintenance := NewMockMaintenance()
			f := newEtcdControllerTestRunner(t, &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance})

			e := etcdControllerFixtures(t)
			e.Status.Phase = etcdv1alpha1.ClusterPhaseRunning
			f.RegisterEtcdClusterFixture(e)
			cluster := NewEtcdCluster(e, f.c.clusterDomain, nil)
			cluster.registerFundamentalObjectOfEtcdCluster(f)
			for _, v := range cluster.AllMembers() {
				v.Labels[etcd.LabelNameEtcdVersion] = "v3.3.0"
				podIsReady(v)
				f.RegisterPodFixture(v)
			}
			tempMemberPod := cluster.newTemporaryMemberPodSpec(
				fmt.Sprintf("%s-%d", cluster.Name, cluster.Spec.Members+1),
				defaultEtcdVersion,
				[]string{},
			)
			podIsReady(tempMemberPod)
			f.RegisterPodFixture(tempMemberPod)

			f.ExpectDeletePod()
			f.ExpectUpdateEtcdCluster()
			f.Run(t, e)
		})

		t.Run("StartMember", func(t *testing.T) {
			t.Parallel()

			etcdMockCluster := NewMockCluster()
			etcdMockMaintenance := NewMockMaintenance()
			f := newEtcdControllerTestRunner(t, &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance})

			e := etcdControllerFixtures(t)
			e.Status.Phase = etcdv1alpha1.ClusterPhaseUpdating
			f.RegisterEtcdClusterFixture(e)
			cluster := NewEtcdCluster(e, f.c.clusterDomain, nil)
			cluster.registerFundamentalObjectOfEtcdCluster(f)
			for _, v := range cluster.AllMembers()[1:] {
				v.Labels[etcd.LabelNameEtcdVersion] = "v3.3.0"
				podIsReady(v)
				f.RegisterPodFixture(v)
			}
			tempMemberPod := cluster.newTemporaryMemberPodSpec(
				fmt.Sprintf("%s-%d", cluster.Name, cluster.Spec.Members+1),
				defaultEtcdVersion,
				[]string{},
			)
			podIsReady(tempMemberPod)
			f.RegisterPodFixture(tempMemberPod)

			f.ExpectCreatePod()
			f.ExpectUpdateEtcdCluster()
			f.Run(t, e)
		})
	})

	t.Run("TeardownUpdating", func(t *testing.T) {
		t.Parallel()

		etcdMockCluster := NewMockCluster()
		etcdMockMaintenance := NewMockMaintenance()
		f := newEtcdControllerTestRunner(t, &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance})

		e := etcdControllerFixtures(t)
		e.Status.Phase = etcdv1alpha1.ClusterPhaseUpdating
		f.RegisterEtcdClusterFixture(e)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, nil)
		cluster.registerFundamentalObjectOfEtcdCluster(f)
		for _, v := range cluster.AllMembers() {
			podIsReady(v)
			f.RegisterPodFixture(v)
		}
		tempMemberPod := cluster.newTemporaryMemberPodSpec(
			fmt.Sprintf("%s-%d", cluster.Name, cluster.Spec.Members+1),
			defaultEtcdVersion,
			[]string{},
		)
		podIsReady(tempMemberPod)
		f.RegisterPodFixture(tempMemberPod)

		f.ExpectDeletePod()
		f.ExpectUpdateEtcdCluster()
		f.Run(t, e)
	})
}

func etcdControllerFixtures(t *testing.T) *etcdv1alpha1.EtcdCluster {
	return &etcdv1alpha1.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      normalizeName(t.Name()),
			Namespace: metav1.NamespaceDefault,
		},
		Spec: etcdv1alpha1.EtcdClusterSpec{
			Members: 3,
		},
	}
}

func podIsReady(pod *corev1.Pod) {
	pod.CreationTimestamp = metav1.Now()
	pod.Status.Phase = corev1.PodRunning
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "etcd", Ready: true}}
}

func (c *EtcdCluster) registerFundamentalObjectOfEtcdCluster(f *etcdControllerTestRunner) {
	ca, _ := c.CA(nil)
	serverS, _ := c.ServerCertSecret(ca)
	clientS, _ := c.ClientCertSecret(ca)
	c.SetCASecret(ca)
	c.SetServerCertSecret(serverS)
	f.RegisterSecretFixture(ca)
	f.RegisterSecretFixture(serverS)
	f.RegisterSecretFixture(clientS)
	f.RegisterServiceFixture(c.DiscoveryService())
	f.RegisterServiceFixture(c.ClientService())
}

type MockCluster struct {
	members []*etcdserverpb.Member
}

func NewMockCluster() *MockCluster {
	return &MockCluster{members: make([]*etcdserverpb.Member, 0)}
}

func (m *MockCluster) AddMember(member *etcdserverpb.Member) {
	member.ID = rand.Uint64()
	m.members = append(m.members, member)
}

func (m *MockCluster) MemberList(_ context.Context) (*clientv3.MemberListResponse, error) {
	return &clientv3.MemberListResponse{Members: m.members}, nil
}

func (m *MockCluster) MemberAdd(_ context.Context, peerAddrs []string) (*clientv3.MemberAddResponse, error) {
	member := &etcdserverpb.Member{PeerURLs: peerAddrs, ID: rand.Uint64()}
	m.members = append(m.members, member)

	return &clientv3.MemberAddResponse{Member: member, Members: m.members}, nil
}

func (m *MockCluster) MemberAddAsLearner(ctx context.Context, peerAddrs []string) (*clientv3.MemberAddResponse, error) {
	panic("implement me")
}

func (m *MockCluster) MemberRemove(_ context.Context, id uint64) (*clientv3.MemberRemoveResponse, error) {
	for i, v := range m.members {
		if v.ID == id {
			m.members = append(m.members[:i], m.members[i+1:]...)
			break
		}
	}

	return &clientv3.MemberRemoveResponse{}, nil
}

func (m *MockCluster) MemberUpdate(ctx context.Context, id uint64, peerAddrs []string) (*clientv3.MemberUpdateResponse, error) {
	panic("implement me")
}

func (m *MockCluster) MemberPromote(ctx context.Context, id uint64) (*clientv3.MemberPromoteResponse, error) {
	panic("implement me")
}

type MockMaintenance struct {
}

func NewMockMaintenance() *MockMaintenance {
	return &MockMaintenance{}
}

func (m *MockMaintenance) AlarmList(ctx context.Context) (*clientv3.AlarmResponse, error) {
	panic("implement me")
}

func (m *MockMaintenance) AlarmDisarm(ctx context.Context, alerm *clientv3.AlarmMember) (*clientv3.AlarmResponse, error) {
	panic("implement me")
}

func (m *MockMaintenance) Defragment(ctx context.Context, endpoint string) (*clientv3.DefragmentResponse, error) {
	panic("implement me")
}

func (m *MockMaintenance) Status(ctx context.Context, endpoint string) (*clientv3.StatusResponse, error) {
	return &clientv3.StatusResponse{
		Header: &etcdserverpb.ResponseHeader{},
	}, nil
}

func (m *MockMaintenance) HashKV(ctx context.Context, endpoint string, rev int64) (*clientv3.HashKVResponse, error) {
	panic("implement me")
}

func (m *MockMaintenance) Snapshot(ctx context.Context) (io.ReadCloser, error) {
	panic("implement me")
}

func (m *MockMaintenance) MoveLeader(ctx context.Context, transfereeID uint64) (*clientv3.MoveLeaderResponse, error) {
	panic("implement me")
}
