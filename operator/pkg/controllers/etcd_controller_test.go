package controllers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.f110.dev/heimdallr/operator/pkg/api/etcd"
	etcdv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha1"
	"go.f110.dev/heimdallr/pkg/logger"
)

func TestEtcdController(t *testing.T) {
	t.Run("CreatingFirstMember", func(t *testing.T) {
		t.Parallel()

		// In this case, we don't need mocking etcd client.
		f, _ := newEtcdControllerTestRunner(t)

		e := etcdControllerFixtures(t, etcdv1alpha1.ClusterPhasePending)
		f.RegisterEtcdClusterFixture(e)

		// Setup
		f.ExpectUpdateEtcdClusterStatus()
		f.ExpectCreateSecret()
		f.ExpectCreateSecret()
		f.ExpectCreateSecret()
		// Create first node
		f.ExpectCreatePod()
		f.ExpectCreateService()
		f.ExpectCreateService()
		f.ExpectUpdateEtcdClusterStatus()
		f.Run(t, e)

		member, err := f.coreClient.CoreV1().Pods(e.Namespace).Get(context.TODO(), fmt.Sprintf("%s-1", e.Name), metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}

		assert.Contains(t, member.Spec.Containers[0].Command, "--initial-cluster-state=new")
	})

	t.Run("CreatingMember", func(t *testing.T) {
		t.Parallel()

		f, _ := newEtcdControllerTestRunner(t)

		e := etcdControllerFixtures(t, etcdv1alpha1.ClusterPhaseCreating)
		f.RegisterEtcdClusterFixture(e)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(f)
		member := cluster.AllMembers()[0]
		podIsReady(member)
		f.RegisterPodFixture(member)

		f.ExpectCreatePod()
		f.ExpectUpdateEtcdClusterStatus()
		f.Run(t, e)

		member, err := f.coreClient.CoreV1().Pods(e.Namespace).Get(context.TODO(), fmt.Sprintf("%s-2", e.Name), metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		assert.Contains(t, member.Spec.Containers[0].Command, "--initial-cluster-state=existing")
		portNames := make([]string, 0)
		for _, v := range member.Spec.Containers[0].Ports {
			portNames = append(portNames, v.Name)
		}
		assert.Contains(t, portNames, "metrics")
	})

	t.Run("PreparingUpdate", func(t *testing.T) {
		t.Parallel()

		f, _ := newEtcdControllerTestRunner(t)

		e := etcdControllerFixtures(t, etcdv1alpha1.ClusterPhaseRunning)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(f)
		for _, v := range cluster.AllMembers() {
			podIsReady(v)
			f.RegisterPodFixture(v)
		}
		e.Spec.Version = "v3.3.0"
		f.RegisterEtcdClusterFixture(e)

		f.ExpectCreatePod()
		f.ExpectUpdateEtcdClusterStatus()
		f.Run(t, e)

		member, err := f.coreClient.CoreV1().Pods(e.Namespace).Get(context.TODO(), fmt.Sprintf("%s-4", e.Name), metav1.GetOptions{})
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

			f, _ := newEtcdControllerTestRunner(t)

			e := etcdControllerFixtures(t, etcdv1alpha1.ClusterPhaseRunning)
			f.RegisterEtcdClusterFixture(e)
			cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
			cluster.registerBasicObjectOfEtcdCluster(f)
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
			f.ExpectUpdateEtcdClusterStatus()
			f.Run(t, e)
		})

		t.Run("StartMember", func(t *testing.T) {
			t.Parallel()

			f, _ := newEtcdControllerTestRunner(t)

			e := etcdControllerFixtures(t, etcdv1alpha1.ClusterPhaseUpdating)
			f.RegisterEtcdClusterFixture(e)
			cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
			cluster.registerBasicObjectOfEtcdCluster(f)
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
			f.ExpectUpdateEtcdClusterStatus()
			f.Run(t, e)
		})
	})

	t.Run("TeardownUpdating", func(t *testing.T) {
		t.Parallel()

		f, _ := newEtcdControllerTestRunner(t)

		e := etcdControllerFixtures(t, etcdv1alpha1.ClusterPhaseUpdating)
		f.RegisterEtcdClusterFixture(e)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(f)
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
		f.ExpectUpdateEtcdClusterStatus()
		f.Run(t, e)
	})

	t.Run("Repair", func(t *testing.T) {
		t.Parallel()

		f, _ := newEtcdControllerTestRunner(t)

		e := etcdControllerFixtures(t, etcdv1alpha1.ClusterPhaseRunning)
		f.RegisterEtcdClusterFixture(e)
		cluster := NewEtcdCluster(e, f.c.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(f)
		cluster.AllMembers()[0].Status.Phase = corev1.PodSucceeded
		for _, v := range cluster.AllMembers()[1:] {
			podIsReady(v)
		}
		f.RegisterPodFixture(cluster.AllMembers()...)

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

		e := etcdControllerFixtures(t, etcdv1alpha1.ClusterPhaseRunning)
		e.Spec.Backup = &etcdv1alpha1.BackupSpec{
			IntervalInSecond: 30,
			Storage: etcdv1alpha1.BackupStorageSpec{
				MinIO: &etcdv1alpha1.BackupStorageMinIOSpec{
					ServiceSelector: etcdv1alpha1.ObjectSelector{Name: minIOService.Name, Namespace: minIOService.Namespace},
					CredentialSelector: etcdv1alpha1.AWSCredentialSelector{
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
			podIsReady(v)
			f.RegisterPodFixture(v)
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

		updatedEC, err := f.client.EtcdV1alpha1().EtcdClusters(cluster.Namespace).Get(context.TODO(), cluster.Name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}

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

		e := etcdControllerFixtures(t, etcdv1alpha1.ClusterPhaseRunning)
		e.Spec.Backup = &etcdv1alpha1.BackupSpec{
			IntervalInSecond: 30,
			Storage: etcdv1alpha1.BackupStorageSpec{
				MinIO: &etcdv1alpha1.BackupStorageMinIOSpec{
					ServiceSelector: etcdv1alpha1.ObjectSelector{Name: minIOService.Name, Namespace: minIOService.Namespace},
					CredentialSelector: etcdv1alpha1.AWSCredentialSelector{
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
			podIsReady(v)
			f.RegisterPodFixture(v)
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

	e := etcdControllerFixtures(t, etcdv1alpha1.ClusterPhaseRunning)
	e.Spec.Backup = &etcdv1alpha1.BackupSpec{
		IntervalInSecond: 30,
		Storage: etcdv1alpha1.BackupStorageSpec{
			MinIO: &etcdv1alpha1.BackupStorageMinIOSpec{
				ServiceSelector: etcdv1alpha1.ObjectSelector{Name: "test", Namespace: metav1.NamespaceDefault},
				CredentialSelector: etcdv1alpha1.AWSCredentialSelector{
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
	e.Status.Backup = &etcdv1alpha1.BackupStatus{
		Succeeded: true,
		History: []etcdv1alpha1.BackupStatusHistory{
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
		v.Status.Phase = corev1.PodSucceeded
		f.RegisterPodFixture(v)
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

	updatedEC, err := f.client.EtcdV1alpha1().EtcdClusters(cluster.Namespace).Get(context.TODO(), cluster.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, "backup/latest", updatedEC.Status.RestoreFrom)
}

func etcdControllerFixtures(t *testing.T, phase etcdv1alpha1.EtcdClusterPhase) *etcdv1alpha1.EtcdCluster {
	return &etcdv1alpha1.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      normalizeName(t.Name()),
			Namespace: metav1.NamespaceDefault,
		},
		Spec: etcdv1alpha1.EtcdClusterSpec{
			Members: 3,
		},
		Status: etcdv1alpha1.EtcdClusterStatus{
			Phase: phase,
		},
	}
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
	pod.CreationTimestamp = metav1.Now()
	pod.Status.Phase = corev1.PodRunning
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "etcd", Ready: true}}
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
}
