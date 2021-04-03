package controllers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.f110.dev/heimdallr/operator/pkg/api/etcd"
	etcdv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
	"go.f110.dev/heimdallr/pkg/logger"
)

func TestEtcdController(t *testing.T) {
	etcdClusterBase := etcd.Factory(nil,
		k8sfactory.Name(normalizeName(t.Name())),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.UID(),
		k8sfactory.Created,
		etcd.Member(3),
		etcd.EnableAntiAffinity,
	)

	t.Run("CreatingFirstMember", func(t *testing.T) {
		t.Parallel()

		// In this case, we don't need mocking etcd client.
		f, _ := newEtcdControllerTestRunner(t)

		e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.ClusterPhasePending))
		f.RegisterFixtures(e)

		// Setup
		f.ExpectUpdateEtcdClusterStatus()
		f.ExpectCreateSecret()
		f.ExpectCreateSecret()
		f.ExpectCreateSecret()
		f.ExpectCreateServiceAccount()
		f.ExpectCreateRole()
		f.ExpectCreateRoleBinding()
		// Create first node
		f.ExpectCreatePod()
		f.ExpectCreateService()
		f.ExpectCreateService()
		f.ExpectUpdateEtcdClusterStatus()
		f.Run(t, e)

		pods, err := f.coreClient.CoreV1().Pods(e.Namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: etcd.LabelNameClusterName + "=" + e.Name})
		require.NoError(t, err)
		require.Len(t, pods.Items, 1)

		assert.Contains(t, pods.Items[0].Spec.Containers[0].Args[1], "--initial-cluster-state=new")
		require.NotNil(t, pods.Items[0].Spec.Affinity)
		assert.NotNil(t, pods.Items[0].Spec.Affinity.PodAntiAffinity)
	})

	t.Run("CreatingMember", func(t *testing.T) {
		t.Parallel()

		f, _ := newEtcdControllerTestRunner(t)

		e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.ClusterPhaseCreating))
		cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(f)
		member := cluster.AllMembers()[0]
		member.Pod = k8sfactory.PodFactory(member.Pod, k8sfactory.Ready)
		f.RegisterFixtures(e, member.Pod)

		f.ExpectCreatePod()
		f.ExpectUpdateEtcdClusterStatus()
		f.Run(t, e)

		pods, err := f.coreClient.CoreV1().Pods(e.Namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: etcd.LabelNameClusterName + "=" + e.Name})
		require.NoError(t, err)
		assert.Len(t, pods.Items, 2)

		found := false
		for _, v := range pods.Items {
			if strings.Contains(v.Spec.Containers[0].Args[1], "--initial-cluster-state=existing") {
				if found {
					assert.Fail(t, "Both nodes has initial-cluster-state=existing")
				}

				found = true
			}
		}
		assert.True(t, found, "Both nodes has initial-cluster-state=new")

		portNames := make([]string, 0)
		for _, v := range member.Pod.Spec.Containers[0].Ports {
			portNames = append(portNames, v.Name)
		}
		assert.Contains(t, portNames, "metrics")
	})

	t.Run("PreparingUpdate", func(t *testing.T) {
		t.Parallel()

		f, _ := newEtcdControllerTestRunner(t)

		e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.ClusterPhaseRunning), etcd.Ready)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(f)
		for _, v := range cluster.AllMembers() {
			v.Pod = k8sfactory.PodFactory(v.Pod, k8sfactory.Ready)
			f.RegisterPodFixture(v.Pod)
		}
		e = etcd.Factory(e, etcd.Version("v3.3.0"))
		f.RegisterEtcdClusterFixture(e)

		f.ExpectCreatePod()
		f.ExpectUpdateEtcdClusterStatus()
		f.Run(t, e)

		pods, err := f.coreClient.CoreV1().Pods(e.Namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: etcd.LabelNameClusterName + "=" + e.Name})
		require.NoError(t, err)
		require.Len(t, pods.Items, 4)

		var temporaryMember *corev1.Pod
		for _, v := range pods.Items {
			if metav1.HasAnnotation(v.ObjectMeta, etcd.AnnotationKeyTemporaryMember) {
				temporaryMember = &v
				break
			}
		}
		require.NotNil(t, temporaryMember, "Could not find temporary member")
		assert.Contains(t, temporaryMember.Spec.Containers[0].Args[1], "--initial-cluster-state=existing")
		assert.Contains(t, temporaryMember.Annotations, etcd.AnnotationKeyTemporaryMember)
		assert.Nil(t, temporaryMember.Spec.Affinity)
	})

	t.Run("UpdatingMember", func(t *testing.T) {
		t.Parallel()

		t.Run("DeleteMember", func(t *testing.T) {
			t.Parallel()

			f, _ := newEtcdControllerTestRunner(t)

			e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.ClusterPhaseRunning), etcd.Ready)
			cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
			cluster.registerBasicObjectOfEtcdCluster(f)
			for _, v := range cluster.AllMembers() {
				v.Pod.Labels[etcd.LabelNameEtcdVersion] = "v3.3.0"
				f.RegisterPodFixture(k8sfactory.PodFactory(v.Pod, k8sfactory.Ready))
			}
			tempMemberPod := cluster.newTemporaryMemberPodSpec(defaultEtcdVersion, []string{})
			f.RegisterFixtures(e, k8sfactory.PodFactory(tempMemberPod, k8sfactory.Ready))

			f.ExpectDeletePod()
			f.ExpectUpdateEtcdClusterStatus()
			f.Run(t, e)
		})

		t.Run("StartMember", func(t *testing.T) {
			t.Parallel()

			f, _ := newEtcdControllerTestRunner(t)

			e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.ClusterPhaseUpdating), etcd.Ready)
			cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
			cluster.registerBasicObjectOfEtcdCluster(f)
			for _, v := range cluster.AllMembers()[1:] {
				v.Pod.Labels[etcd.LabelNameEtcdVersion] = "v3.3.0"
				f.RegisterPodFixture(k8sfactory.PodFactory(v.Pod, k8sfactory.Ready))
			}
			tempMemberPod := cluster.newTemporaryMemberPodSpec(defaultEtcdVersion, []string{})
			f.RegisterFixtures(e, k8sfactory.PodFactory(tempMemberPod, k8sfactory.Ready))

			f.ExpectCreatePod()
			f.ExpectUpdateEtcdClusterStatus()
			f.Run(t, e)
		})
	})

	t.Run("TeardownUpdating", func(t *testing.T) {
		t.Parallel()

		f, _ := newEtcdControllerTestRunner(t)

		e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.ClusterPhaseUpdating), etcd.Ready)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(f)
		for _, v := range cluster.AllMembers() {
			f.RegisterPodFixture(k8sfactory.PodFactory(v.Pod, k8sfactory.Ready))
		}
		tempMemberPod := cluster.newTemporaryMemberPodSpec(defaultEtcdVersion, []string{})
		f.RegisterFixtures(e, tempMemberPod, k8sfactory.PodFactory(tempMemberPod, k8sfactory.Ready))

		f.ExpectDeletePod()
		f.ExpectUpdateEtcdClusterStatus()
		f.Run(t, e)
	})

	t.Run("Repair", func(t *testing.T) {
		t.Parallel()

		f, _ := newEtcdControllerTestRunner(t)

		e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.ClusterPhaseRunning), etcd.Ready)
		f.RegisterEtcdClusterFixture(e)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(f)
		for i, v := range cluster.AllMembers() {
			v.Pod = k8sfactory.PodFactory(v.Pod, k8sfactory.Ready)

			if i == 0 {
				v.Pod.Status.Phase = corev1.PodSucceeded
			}
		}
		for _, v := range cluster.AllMembers() {
			f.RegisterPodFixture(v.Pod)
		}

		f.ExpectDeletePod()
		f.ExpectUpdateEtcdClusterStatus()
		f.Run(t, e)
	})
}

func TestEtcdController_Backup(t *testing.T) {
	etcdClusterBase := etcd.Factory(nil,
		k8sfactory.Name(normalizeName(t.Name())),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.UID(),
		k8sfactory.Created,
		etcd.Member(3),
		etcd.EnableAntiAffinity,
	)

	t.Run("MinIO", func(t *testing.T) {
		t.Parallel()

		f, _ := newEtcdControllerTestRunner(t)

		minIOService, minIOSecret := minIOFixtures()
		f.RegisterFixtures(minIOService, minIOSecret)

		e := etcd.Factory(etcdClusterBase,
			k8sfactory.Name(normalizeName(t.Name())),
			etcd.Phase(etcdv1alpha2.ClusterPhaseRunning),
		)
		e.Spec.Backup = &etcdv1alpha2.BackupSpec{
			IntervalInSecond: 30,
			Storage: etcdv1alpha2.BackupStorageSpec{
				MinIO: &etcdv1alpha2.BackupStorageMinIOSpec{
					ServiceSelector: etcdv1alpha2.ObjectSelector{Name: minIOService.Name, Namespace: minIOService.Namespace},
					CredentialSelector: etcdv1alpha2.AWSCredentialSelector{
						Name:               minIOSecret.Name,
						Namespace:          minIOSecret.Namespace,
						AccessKeyIDKey:     "accesskey",
						SecretAccessKeyKey: "secretkey",
					},
					Path:   "/backup",
					Bucket: "etcdcontroller",
				},
			},
			MaxBackups: 0,
		}
		f.RegisterEtcdClusterFixture(e)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(f)
		for _, v := range cluster.AllMembers() {
			f.RegisterPodFixture(k8sfactory.PodFactory(v.Pod, k8sfactory.Ready))
		}

		// Get bucket location
		f.transport.RegisterResponder(
			http.MethodGet,
			"/etcdcontroller/?location=",
			httpmock.NewStringResponder(http.StatusOK, `<LocationConstraint>us-west-2</LocationConstraint>`),
		)
		// Put object
		f.transport.RegisterResponder(
			http.MethodPut,
			fmt.Sprintf(`=~/backup/%s_\d+\z`, strings.Replace(t.Name(), "/", "-", -1)),
			httpmock.NewStringResponder(http.StatusOK, ""),
		)
		f.ExpectUpdateEtcdClusterStatus()
		f.Run(t, e)

		updatedEC, err := f.client.EtcdV1alpha2().EtcdClusters(cluster.Namespace).Get(context.TODO(), cluster.Name, metav1.GetOptions{})
		require.NoError(t, err)

		assert.NotNil(t, updatedEC.Status.Backup)
		assert.True(t, updatedEC.Status.Backup.Succeeded)
		assert.Len(t, updatedEC.Status.Backup.History, 1)
		assert.Equal(t, updatedEC.Status.Backup.LastSucceededTime, updatedEC.Status.Backup.History[0].ExecuteTime)
	})

	t.Run("MinIO_Rotate", func(t *testing.T) {
		t.Parallel()

		f, _ := newEtcdControllerTestRunner(t)

		minIOService, minIOSecret := minIOFixtures()
		f.RegisterFixtures(minIOService, minIOSecret)

		e := etcd.Factory(etcdClusterBase,
			k8sfactory.Name(normalizeName(t.Name())),
			etcd.Phase(etcdv1alpha2.ClusterPhaseRunning),
			etcd.Backup(30, 5),
			etcd.BackupToMinIO(
				"etcdcontroller",
				"/backup",
				false,
				minIOService.Name,
				minIOService.Namespace,
				etcdv1alpha2.AWSCredentialSelector{
					Name:               minIOSecret.Name,
					Namespace:          minIOSecret.Namespace,
					AccessKeyIDKey:     "accesskey",
					SecretAccessKeyKey: "secretkey",
				},
			),
		)
		f.RegisterEtcdClusterFixture(e)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(f)
		for _, v := range cluster.AllMembers() {
			f.RegisterPodFixture(k8sfactory.PodFactory(v.Pod, k8sfactory.Ready))
		}

		// Get bucket location
		f.transport.RegisterResponder(
			http.MethodGet,
			"/etcdcontroller/?location=",
			httpmock.NewStringResponder(http.StatusOK, `<LocationConstraint>us-west-2</LocationConstraint>`),
		)
		// Put object
		f.transport.RegisterResponder(
			http.MethodPut,
			fmt.Sprintf(`=~/backup/%s_\d+\z`, strings.Replace(t.Name(), "/", "-", -1)),
			httpmock.NewStringResponder(http.StatusOK, ""),
		)
		f.ExpectUpdateEtcdClusterStatus()
		f.Run(t, e)
	})
}

func TestEtcdController_Restore(t *testing.T) {
	f, _ := newEtcdControllerTestRunner(t)

	e := etcd.Factory(nil,
		k8sfactory.Name(normalizeName(t.Name())),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.UID(),
		k8sfactory.Created,
		etcd.Member(3),
		etcd.EnableAntiAffinity,
		etcd.Ready,
		etcd.Backup(30, 5),
		etcd.BackupToMinIO(
			"etcdcontroller",
			"/backup",
			false,
			"test",
			metav1.NamespaceDefault,
			etcdv1alpha2.AWSCredentialSelector{
				Name:               "test",
				Namespace:          metav1.NamespaceDefault,
				AccessKeyIDKey:     "accesskey",
				SecretAccessKeyKey: "secretkey",
			},
		),
	)
	e.Status.Backup = &etcdv1alpha2.BackupStatus{
		Succeeded: true,
		History: []etcdv1alpha2.BackupStatusHistory{
			{
				Succeeded: true,
				Path:      "backup/latest",
			},
		},
	}
	f.RegisterEtcdClusterFixture(e)
	cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
	cluster.registerBasicObjectOfEtcdCluster(f)
	for _, v := range cluster.AllMembers() {
		v.Pod = k8sfactory.PodFactory(v.Pod, k8sfactory.Ready)

		v.Pod.Status.Phase = corev1.PodSucceeded
		f.RegisterPodFixture(v.Pod)
	}

	// Get bucket location
	f.transport.RegisterResponder(
		http.MethodGet,
		"/etcdcontroller/?location=",
		httpmock.NewStringResponder(http.StatusOK, `<LocationConstraint>us-west-2</LocationConstraint>`),
	)
	// Put object
	f.transport.RegisterResponder(
		http.MethodPut,
		fmt.Sprintf(`=~/backup/%s_\d+\z`, strings.Replace(t.Name(), "/", "-", -1)),
		httpmock.NewStringResponder(http.StatusOK, ""),
	)

	// Delete all members
	f.ExpectDeletePod()
	f.ExpectDeletePod()
	f.ExpectDeletePod()
	f.ExpectUpdateEtcdClusterStatus()
	f.ExpectUpdateEtcdClusterStatus()
	f.Run(t, e)

	updatedEC, err := f.client.EtcdV1alpha2().EtcdClusters(cluster.Namespace).Get(context.TODO(), cluster.Name, metav1.GetOptions{})
	require.NoError(t, err)

	require.NotNil(t, updatedEC.Status.Restored)
	assert.Equal(t, "backup/latest", updatedEC.Status.Restored.Path)
	assert.True(t, updatedEC.Status.Restored.Completed)
}

func minIOFixtures() (*corev1.Service, *corev1.Secret) {
	svc := k8sfactory.ServiceFactory(nil,
		k8sfactory.Name("minio"),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.Port("http", corev1.ProtocolTCP, 80),
	)
	secret := k8sfactory.SecretFactory(nil,
		k8sfactory.Name("minio"),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.Data("accesskey", []byte("accesskey")),
		k8sfactory.Data("secret", []byte("secret")),
	)

	return svc, secret
}

func (c *EtcdCluster) registerBasicObjectOfEtcdCluster(f *etcdControllerTestRunner) {
	ca, _ := c.CA()
	serverS, _ := c.ServerCertSecret()
	clientS, _ := c.ClientCertSecret()
	c.SetCASecret(ca)
	c.SetServerCertSecret(serverS)
	f.RegisterSecretFixture(ca)
	f.RegisterSecretFixture(serverS)
	f.RegisterSecretFixture(clientS)
	f.RegisterServiceFixture(c.DiscoveryService())
	f.RegisterServiceFixture(c.ClientService())
	f.RegisterServiceAccountFixture(c.ServiceAccount())
	f.RegisterRoleFixture(c.EtcdRole())
	f.RegisterRoleBindingFixture(c.EtcdRoleBinding())
}
