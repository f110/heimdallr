package controllers

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/uuid"

	"go.f110.dev/heimdallr/operator/pkg/api/etcd"
	etcdv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha2"
	"go.f110.dev/heimdallr/pkg/logger"
)

func TestEtcdController(t *testing.T) {
	t.Run("CreatingFirstMember", func(t *testing.T) {
		t.Parallel()

		// In this case, we don't need mocking etcd client.
		f, _ := newEtcdControllerTestRunner(t)

		e := etcdClusterFixtures(t, etcdv1alpha2.ClusterPhasePending)
		f.RegisterEtcdClusterFixture(e)

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
		assert.Len(t, pods.Items, 1)

		assert.Contains(t, pods.Items[0].Spec.Containers[0].Args[1], "--initial-cluster-state=new")
		require.NotNil(t, pods.Items[0].Spec.Affinity)
		assert.NotNil(t, pods.Items[0].Spec.Affinity.PodAntiAffinity)
	})

	t.Run("CreatingMember", func(t *testing.T) {
		t.Parallel()

		f, _ := newEtcdControllerTestRunner(t)

		e := etcdClusterFixtures(t, etcdv1alpha2.ClusterPhaseCreating)
		f.RegisterEtcdClusterFixture(e)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(f)
		member := cluster.AllMembers()[0]
		podIsReady(member.Pod)
		f.RegisterPodFixture(member.Pod)

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

		e := etcdClusterFixtures(t, etcdv1alpha2.ClusterPhaseRunning, etcdClusterReady)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(f)
		for _, v := range cluster.AllMembers() {
			podIsReady(v.Pod)
			f.RegisterPodFixture(v.Pod)
		}
		e.Spec.Version = "v3.3.0"
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

			e := etcdClusterFixtures(t, etcdv1alpha2.ClusterPhaseRunning, etcdClusterReady)
			f.RegisterEtcdClusterFixture(e)
			cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
			cluster.registerBasicObjectOfEtcdCluster(f)
			for _, v := range cluster.AllMembers() {
				v.Pod.Labels[etcd.LabelNameEtcdVersion] = "v3.3.0"
				podIsReady(v.Pod)
				f.RegisterPodFixture(v.Pod)
			}
			tempMemberPod := cluster.newTemporaryMemberPodSpec(defaultEtcdVersion, []string{})
			podIsReady(tempMemberPod)
			f.RegisterPodFixture(tempMemberPod)

			f.ExpectDeletePod()
			f.ExpectUpdateEtcdClusterStatus()
			f.Run(t, e)
		})

		t.Run("StartMember", func(t *testing.T) {
			t.Parallel()

			f, _ := newEtcdControllerTestRunner(t)

			e := etcdClusterFixtures(t, etcdv1alpha2.ClusterPhaseUpdating, etcdClusterReady)
			f.RegisterEtcdClusterFixture(e)
			cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
			cluster.registerBasicObjectOfEtcdCluster(f)
			for _, v := range cluster.AllMembers()[1:] {
				v.Pod.Labels[etcd.LabelNameEtcdVersion] = "v3.3.0"
				podIsReady(v.Pod)
				f.RegisterPodFixture(v.Pod)
			}
			tempMemberPod := cluster.newTemporaryMemberPodSpec(defaultEtcdVersion, []string{})
			podIsReady(tempMemberPod)
			f.RegisterPodFixture(tempMemberPod)

			f.ExpectCreatePod()
			f.ExpectUpdateEtcdClusterStatus()
			f.Run(t, e)
		})
	})

	t.Run("TeardownUpdating", func(t *testing.T) {
		t.Parallel()

		f, _ := newEtcdControllerTestRunner(t)

		e := etcdClusterFixtures(t, etcdv1alpha2.ClusterPhaseUpdating, etcdClusterReady)
		f.RegisterEtcdClusterFixture(e)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(f)
		for _, v := range cluster.AllMembers() {
			podIsReady(v.Pod)
			f.RegisterPodFixture(v.Pod)
		}
		tempMemberPod := cluster.newTemporaryMemberPodSpec(defaultEtcdVersion, []string{})
		podIsReady(tempMemberPod)
		f.RegisterPodFixture(tempMemberPod)

		f.ExpectDeletePod()
		f.ExpectUpdateEtcdClusterStatus()
		f.Run(t, e)
	})

	t.Run("Repair", func(t *testing.T) {
		t.Parallel()

		f, _ := newEtcdControllerTestRunner(t)

		e := etcdClusterFixtures(t, etcdv1alpha2.ClusterPhaseRunning, etcdClusterReady)
		f.RegisterEtcdClusterFixture(e)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(f)
		for i, v := range cluster.AllMembers() {
			podIsReady(v.Pod)

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
	t.Run("MinIO", func(t *testing.T) {
		t.Parallel()

		f, _ := newEtcdControllerTestRunner(t)

		minIOService, minIOSecret := minIOFixtures()
		f.RegisterFixtures(minIOService, minIOSecret)

		e := etcdClusterFixtures(t, etcdv1alpha2.ClusterPhaseRunning)
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
			podIsReady(v.Pod)
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

		e := etcdClusterFixtures(t, etcdv1alpha2.ClusterPhaseRunning)
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
			MaxBackups: 5,
		}
		f.RegisterEtcdClusterFixture(e)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(f)
		for _, v := range cluster.AllMembers() {
			podIsReady(v.Pod)
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
		f.ExpectUpdateEtcdClusterStatus()
		f.Run(t, e)
	})
}

func TestEtcdController_Restore(t *testing.T) {
	f, _ := newEtcdControllerTestRunner(t)

	e := etcdClusterFixtures(t, etcdv1alpha2.ClusterPhaseRunning, etcdClusterReady)
	e.Spec.Backup = &etcdv1alpha2.BackupSpec{
		IntervalInSecond: 30,
		Storage: etcdv1alpha2.BackupStorageSpec{
			MinIO: &etcdv1alpha2.BackupStorageMinIOSpec{
				ServiceSelector: etcdv1alpha2.ObjectSelector{Name: "test", Namespace: metav1.NamespaceDefault},
				CredentialSelector: etcdv1alpha2.AWSCredentialSelector{
					Name:               "test",
					Namespace:          metav1.NamespaceDefault,
					AccessKeyIDKey:     "accesskey",
					SecretAccessKeyKey: "secretkey",
				},
				Path:   "/backup",
				Bucket: "etcdcontroller",
			},
		},
		MaxBackups: 5,
	}
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
		podIsReady(v.Pod)

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
	assert.False(t, updatedEC.Status.Restored.Completed)
}

type etcdClusterOpt func(e *etcdv1alpha2.EtcdCluster)

func etcdClusterFixtures(t *testing.T, phase etcdv1alpha2.EtcdClusterPhase, opt ...etcdClusterOpt) *etcdv1alpha2.EtcdCluster {
	ec := &etcdv1alpha2.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:              normalizeName(t.Name()),
			Namespace:         metav1.NamespaceDefault,
			UID:               uuid.NewUUID(),
			CreationTimestamp: metav1.Now(),
		},
		Spec: etcdv1alpha2.EtcdClusterSpec{
			Members:      3,
			AntiAffinity: true,
		},
		Status: etcdv1alpha2.EtcdClusterStatus{
			Phase: phase,
		},
	}
	for _, v := range opt {
		v(ec)
	}

	return ec
}

func minIOFixtures() (*corev1.Service, *corev1.Secret) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "minio",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: 80},
			},
		},
	}
	scr := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "minio",
			Namespace: metav1.NamespaceDefault,
		},
		Data: map[string][]byte{
			"accesskey": []byte("accesskey"),
			"secretkey": []byte("secretkey"),
		},
	}

	return svc, scr
}

func podIsReady(pod *corev1.Pod) {
	if pod.GenerateName != "" && pod.Name == "" {
		pod.Name = pod.GenerateName + randomString(5)
	}
	pod.CreationTimestamp = metav1.Now()
	pod.Status.Phase = corev1.PodRunning
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "etcd", Ready: true}}
	pod.Status.Conditions = append(pod.Status.Conditions, corev1.PodCondition{Type: corev1.PodReady, Status: corev1.ConditionTrue})
}

func (c *EtcdCluster) registerBasicObjectOfEtcdCluster(f *etcdControllerTestRunner) {
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
	f.RegisterServiceAccountFixture(c.ServiceAccount())
	f.RegisterRoleFixture(c.EtcdRole())
	f.RegisterRoleBindingFixture(c.EtcdRoleBinding())
}

func etcdClusterReady(e *etcdv1alpha2.EtcdCluster) {
	now := metav1.Now()
	e.Status.LastReadyTransitionTime = &now
}

var charset = []byte("abcdefghijklmnopqrstuvwxyz0123456789")

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	return string(b)
}
