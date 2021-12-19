package controllers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/api/v3/etcdserverpb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.f110.dev/heimdallr/pkg/k8s/api/etcd"
	etcdv1alpha2 "go.f110.dev/heimdallr/pkg/k8s/api/etcd/v1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/controllers/controllertest"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
	"go.f110.dev/heimdallr/pkg/logger"
)

func TestEtcdController(t *testing.T) {
	etcdClusterBase := etcd.Factory(nil,
		k8sfactory.Name(normalizeName(t.Name())),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.Created,
		etcd.Member(3),
		etcd.EnableAntiAffinity,
		etcd.MemberStatus(nil),
	)

	t.Run("CreatingFirstMember", func(t *testing.T) {
		t.Parallel()

		runner := controllertest.NewTestRunner()
		etcdMockCluster := NewMockCluster()
		etcdMockMaintenance := NewMockMaintenance()
		mockOpt := &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance}
		controller, err := NewEtcdController(
			runner.SharedInformerFactory,
			runner.CoreSharedInformerFactory,
			runner.CoreClient,
			runner.Client,
			nil,
			"cluster.local",
			false,
			nil,
			mockOpt,
		)

		e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.ClusterPhasePending))
		err = runner.Reconcile(controller, e)
		require.NoError(t, err)

		updated := etcd.Factory(e, etcd.Phase(etcdv1alpha2.ClusterPhasePending))
		updated.Status.ClientEndpoint = fmt.Sprintf("https://%s-client.%s.svc.cluster.local:2379", e.Name, e.Namespace)
		updated.Status.ClientCertSecretName = fmt.Sprintf("etcd-%s-client-cert", e.Name)
		runner.AssertUpdateAction(t, "status", updated)
		namespace := k8sfactory.Namespace(e.Namespace)
		runner.AssertCreateAction(t, k8sfactory.SecretFactory(nil, k8sfactory.Namef("etcd-%s-ca", e.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.SecretFactory(nil, k8sfactory.Namef("etcd-%s-server-cert", e.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.SecretFactory(nil, k8sfactory.Namef("etcd-%s-client-cert", e.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.ServiceAccountFactory(nil, k8sfactory.Namef("%s-etcd", e.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.RoleFactory(nil, k8sfactory.Namef("%s-etcd", e.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.RoleBindingFactory(nil, k8sfactory.Namef("%s-etcd", e.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.PodFactory(nil, k8sfactory.Namef("%s-1", e.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.ServiceFactory(nil, k8sfactory.Namef("%s-discovery", e.Name), namespace))
		runner.AssertCreateAction(t, k8sfactory.ServiceFactory(nil, k8sfactory.Namef("%s-client", e.Name), namespace))
		updated = etcd.Factory(e, etcd.Phase(etcdv1alpha2.ClusterPhaseInitializing))
		runner.AssertUpdateAction(t, "status", updated)
		runner.AssertNoUnexpectedAction(t)

		pod, err := runner.CoreClient.CoreV1().Pods(e.Namespace).Get(context.TODO(), fmt.Sprintf("%s-1", e.Name), metav1.GetOptions{})
		require.NoError(t, err)

		assert.Contains(t, pod.Spec.Containers[0].Args[1], "--initial-cluster-state=new")
		require.NotNil(t, pod.Spec.Affinity)
		assert.NotNil(t, pod.Spec.Affinity.PodAntiAffinity)
	})

	t.Run("CreatingMember", func(t *testing.T) {
		t.Parallel()

		runner := controllertest.NewTestRunner()
		etcdMockCluster := NewMockCluster()
		etcdMockMaintenance := NewMockMaintenance()
		mockOpt := &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance}
		controller, err := NewEtcdController(
			runner.SharedInformerFactory,
			runner.CoreSharedInformerFactory,
			runner.CoreClient,
			runner.Client,
			nil,
			"cluster.local",
			false,
			nil,
			mockOpt,
		)
		require.NoError(t, err)

		e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.ClusterPhaseCreating))
		cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(runner)
		member := cluster.AllMembers()[0]
		member.Pod = k8sfactory.PodFactory(member.Pod, k8sfactory.Ready)
		runner.RegisterFixtures(e, member.Pod)

		err = runner.Reconcile(controller, e)
		require.NoError(t, err)

		updated := e.DeepCopy()
		updated.Status.ClientEndpoint = fmt.Sprintf("https://%s-client.%s.svc.cluster.local:2379", e.Name, e.Namespace)
		updated.Status.ClientCertSecretName = fmt.Sprintf("etcd-%s-client-cert", e.Name)
		runner.AssertCreateAction(t, k8sfactory.PodFactory(nil, k8sfactory.Namef("%s-2", e.Name), k8sfactory.Namespace(e.Namespace)))
		runner.AssertUpdateAction(t, "", k8sfactory.PodFactory(member.Pod, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339))))
		runner.AssertUpdateAction(t, "status", updated)
		runner.AssertNoUnexpectedAction(t)

		pods, err := runner.CoreClient.CoreV1().Pods(e.Namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: etcd.LabelNameClusterName + "=" + e.Name})
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

		runner := controllertest.NewTestRunner()
		etcdMockCluster := NewMockCluster()
		etcdMockMaintenance := NewMockMaintenance()
		mockOpt := &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance}
		controller, err := NewEtcdController(
			runner.SharedInformerFactory,
			runner.CoreSharedInformerFactory,
			runner.CoreClient,
			runner.Client,
			nil,
			"cluster.local",
			false,
			nil,
			mockOpt,
		)
		require.NoError(t, err)

		e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.ClusterPhaseRunning), etcd.Ready)
		cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(runner)
		for _, v := range cluster.AllMembers() {
			v.Pod = k8sfactory.PodFactory(v.Pod, k8sfactory.Ready, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339)))
			runner.RegisterFixtures(v.Pod)
			etcdMockCluster.AddMember(&etcdserverpb.Member{Name: v.Pod.Name})
			e.Status.Members = append(e.Status.Members, etcdv1alpha2.MemberStatus{Name: v.Pod.Name})
		}
		e = etcd.Factory(e, etcd.Version("v3.3.0"))

		err = runner.Reconcile(controller, e)
		require.NoError(t, err)

		updated := e.DeepCopy()
		updated.Status.ClientEndpoint = fmt.Sprintf("https://%s-client.%s.svc.cluster.local:2379", e.Name, e.Namespace)
		updated.Status.ClientCertSecretName = fmt.Sprintf("etcd-%s-client-cert", e.Name)
		runner.AssertCreateAction(t, k8sfactory.PodFactory(nil, k8sfactory.Namef("%s-4", e.Name), k8sfactory.Namespace(e.Namespace)))
		runner.AssertUpdateAction(t, "status", updated)
		runner.AssertNoUnexpectedAction(t)

		pods, err := runner.CoreClient.CoreV1().Pods(e.Namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: etcd.LabelNameClusterName + "=" + e.Name})
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

			runner := controllertest.NewTestRunner()
			etcdMockCluster := NewMockCluster()
			etcdMockMaintenance := NewMockMaintenance()
			mockOpt := &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance}
			controller, err := NewEtcdController(
				runner.SharedInformerFactory,
				runner.CoreSharedInformerFactory,
				runner.CoreClient,
				runner.Client,
				nil,
				"cluster.local",
				false,
				nil,
				mockOpt,
			)
			require.NoError(t, err)

			e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.ClusterPhaseRunning), etcd.Ready)
			cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil)
			cluster.registerBasicObjectOfEtcdCluster(runner)
			for _, v := range cluster.AllMembers() {
				v.Pod.Labels[etcd.LabelNameEtcdVersion] = "v3.3.0"
				runner.RegisterFixtures(
					k8sfactory.PodFactory(v.Pod,
						k8sfactory.Ready,
						k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339)),
					),
				)
				etcdMockCluster.AddMember(&etcdserverpb.Member{Name: v.Pod.Name})
				e.Status.Members = append(e.Status.Members, etcdv1alpha2.MemberStatus{Name: v.Pod.Name})
			}
			tempMemberPod := cluster.newTemporaryMemberPodSpec(defaultEtcdVersion, []string{})
			runner.RegisterFixtures(k8sfactory.PodFactory(tempMemberPod, k8sfactory.Ready, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339))))

			err = runner.Reconcile(controller, e)
			require.NoError(t, err)

			updated := etcd.Factory(e, etcd.Phase(etcdv1alpha2.ClusterPhaseUpdating), etcd.CreatedStatus)
			runner.AssertDeleteAction(t, k8sfactory.PodFactory(nil, k8sfactory.Namef("%s-1", e.Name), k8sfactory.Namespace(e.Namespace)))
			runner.AssertUpdateAction(t, "status", updated)
			runner.AssertNoUnexpectedAction(t)
		})

		t.Run("StartMember", func(t *testing.T) {
			t.Parallel()

			runner := controllertest.NewTestRunner()
			etcdMockCluster := NewMockCluster()
			etcdMockMaintenance := NewMockMaintenance()
			mockOpt := &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance}
			controller, err := NewEtcdController(
				runner.SharedInformerFactory,
				runner.CoreSharedInformerFactory,
				runner.CoreClient,
				runner.Client,
				nil,
				"cluster.local",
				false,
				nil,
				mockOpt,
			)
			require.NoError(t, err)

			e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.ClusterPhaseUpdating), etcd.Ready)
			cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil)
			cluster.registerBasicObjectOfEtcdCluster(runner)
			for _, v := range cluster.AllMembers()[1:] {
				v.Pod.Labels[etcd.LabelNameEtcdVersion] = "v3.3.0"
				runner.RegisterFixtures(
					k8sfactory.PodFactory(v.Pod,
						k8sfactory.Ready,
						k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339)),
					),
				)
				etcdMockCluster.AddMember(&etcdserverpb.Member{Name: v.Pod.Name})
				e.Status.Members = append(e.Status.Members, etcdv1alpha2.MemberStatus{Name: v.Pod.Name})
			}
			tempMemberPod := cluster.newTemporaryMemberPodSpec(defaultEtcdVersion, []string{})
			runner.RegisterFixtures(k8sfactory.PodFactory(tempMemberPod, k8sfactory.Ready, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339))))

			err = runner.Reconcile(controller, e)
			require.NoError(t, err)

			updated := etcd.Factory(e, etcd.Phase(etcdv1alpha2.ClusterPhaseUpdating), etcd.CreatedStatus)
			runner.AssertCreateAction(t, k8sfactory.PodFactory(nil, k8sfactory.Namef("%s-1", e.Name), k8sfactory.Namespace(e.Namespace)))
			runner.AssertUpdateAction(t, "status", updated)
			runner.AssertNoUnexpectedAction(t)
		})
	})

	t.Run("TeardownUpdating", func(t *testing.T) {
		t.Parallel()

		runner := controllertest.NewTestRunner()
		etcdMockCluster := NewMockCluster()
		etcdMockMaintenance := NewMockMaintenance()
		mockOpt := &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance}
		controller, err := NewEtcdController(
			runner.SharedInformerFactory,
			runner.CoreSharedInformerFactory,
			runner.CoreClient,
			runner.Client,
			nil,
			"cluster.local",
			false,
			nil,
			mockOpt,
		)
		require.NoError(t, err)

		e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.ClusterPhaseUpdating), etcd.Ready)
		cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(runner)
		for _, v := range cluster.AllMembers() {
			runner.RegisterFixtures(k8sfactory.PodFactory(v.Pod, k8sfactory.Ready, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339))))
			etcdMockCluster.AddMember(&etcdserverpb.Member{Name: v.Pod.Name})
			e.Status.Members = append(e.Status.Members, etcdv1alpha2.MemberStatus{Name: v.Pod.Name})
		}
		tempMemberPod := cluster.newTemporaryMemberPodSpec(defaultEtcdVersion, []string{})
		runner.RegisterFixtures(tempMemberPod, k8sfactory.PodFactory(tempMemberPod, k8sfactory.Ready, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339))))

		err = runner.Reconcile(controller, e)
		require.NoError(t, err)

		updated := etcd.Factory(e, etcd.Phase(etcdv1alpha2.ClusterPhaseUpdating), etcd.CreatedStatus)
		runner.AssertDeleteAction(t, k8sfactory.PodFactory(nil, k8sfactory.Namef("%s-4", e.Name), k8sfactory.Namespace(e.Namespace)))
		runner.AssertUpdateAction(t, "status", updated)
		runner.AssertNoUnexpectedAction(t)
	})

	t.Run("Repair", func(t *testing.T) {
		t.Parallel()

		runner := controllertest.NewTestRunner()
		etcdMockCluster := NewMockCluster()
		etcdMockMaintenance := NewMockMaintenance()
		mockOpt := &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance}
		controller, err := NewEtcdController(
			runner.SharedInformerFactory,
			runner.CoreSharedInformerFactory,
			runner.CoreClient,
			runner.Client,
			nil,
			"cluster.local",
			false,
			nil,
			mockOpt,
		)
		require.NoError(t, err)

		e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.ClusterPhaseRunning), etcd.Ready)
		runner.RegisterFixtures(e)
		cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(runner)
		for i, v := range cluster.AllMembers() {
			v.Pod = k8sfactory.PodFactory(v.Pod, k8sfactory.Ready, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339)))
			etcdMockCluster.AddMember(&etcdserverpb.Member{Name: v.Pod.Name})
			e.Status.Members = append(e.Status.Members, etcdv1alpha2.MemberStatus{Name: v.Pod.Name})

			if i == 0 {
				v.Pod.Status.Phase = corev1.PodSucceeded
			}
		}
		for _, v := range cluster.AllMembers() {
			runner.RegisterFixtures(v.Pod)
		}

		err = runner.Reconcile(controller, e)
		require.NoError(t, err)

		updated := etcd.Factory(e, etcd.Phase(etcdv1alpha2.ClusterPhaseDegrading), etcd.CreatedStatus)
		runner.AssertDeleteAction(t, k8sfactory.PodFactory(nil, k8sfactory.Namef("%s-1", e.Name), k8sfactory.Namespace(e.Namespace)))
		runner.AssertUpdateAction(t, "status", updated)
		runner.AssertNoUnexpectedAction(t)
	})

	t.Run("TemporaryMemberOnly", func(t *testing.T) {
		t.Parallel()

		runner := controllertest.NewTestRunner()
		etcdMockCluster := NewMockCluster()
		etcdMockMaintenance := NewMockMaintenance()
		mockOpt := &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance}
		controller, err := NewEtcdController(
			runner.SharedInformerFactory,
			runner.CoreSharedInformerFactory,
			runner.CoreClient,
			runner.Client,
			nil,
			"cluster.local",
			false,
			nil,
			mockOpt,
		)
		require.NoError(t, err)

		e := etcd.Factory(etcdClusterBase,
			etcd.Phase(etcdv1alpha2.ClusterPhaseRunning),
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
		cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(runner)
		for _, v := range cluster.AllMembers() {
			etcdMockCluster.AddMember(&etcdserverpb.Member{Name: v.Pod.Name})
			e.Status.Members = append(e.Status.Members, etcdv1alpha2.MemberStatus{Name: v.Pod.Name})
		}
		tempMemberPod := cluster.newTemporaryMemberPodSpec(defaultEtcdVersion, []string{})
		// If only exists a temporary member, always failed the readiness probe of the etcd controller.
		// Hence, The status of the Pod is not ready.
		tempMemberPod = k8sfactory.PodFactory(tempMemberPod,
			k8sfactory.NotReady,
			k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339)),
		)
		runner.RegisterFixtures(tempMemberPod)

		err = runner.Reconcile(controller, e)
		require.NoError(t, err)

		updated := etcd.Factory(e, etcd.Phase(etcdv1alpha2.ClusterPhaseInitializing), etcd.CreatedStatus)
		updated.Status.LastReadyTransitionTime = nil
		updated.Status.Restored = &etcdv1alpha2.RestoredStatus{Path: "backup/latest"}
		runner.AssertUpdateAction(t, "status", updated)
		runner.AssertDeleteAction(t, tempMemberPod)
		runner.AssertNoUnexpectedAction(t)
	})
}

func TestEtcdController_Backup(t *testing.T) {
	etcdClusterBase := etcd.Factory(nil,
		k8sfactory.Name(normalizeName(t.Name())),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.Created,
		etcd.Member(3),
		etcd.EnableAntiAffinity,
		etcd.MemberStatus(nil),
	)

	t.Run("MinIO", func(t *testing.T) {
		t.Parallel()

		runner := controllertest.NewTestRunner()
		etcdMockCluster := NewMockCluster()
		etcdMockMaintenance := NewMockMaintenance()
		mockOpt := &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance}
		transport := httpmock.NewMockTransport()
		controller, err := NewEtcdController(
			runner.SharedInformerFactory,
			runner.CoreSharedInformerFactory,
			runner.CoreClient,
			runner.Client,
			nil,
			"cluster.local",
			false,
			transport,
			mockOpt,
		)
		require.NoError(t, err)

		minIOService, minIOSecret := minIOFixtures()
		runner.RegisterFixtures(minIOService, minIOSecret)

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
		cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(runner)
		for _, v := range cluster.AllMembers() {
			runner.RegisterFixtures(k8sfactory.PodFactory(v.Pod, k8sfactory.Ready, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339))))
		}

		// Get bucket location
		transport.RegisterResponder(
			http.MethodGet,
			"/etcdcontroller/?location=",
			httpmock.NewStringResponder(http.StatusOK, `<LocationConstraint>us-west-2</LocationConstraint>`),
		)
		// Put object
		transport.RegisterResponder(
			http.MethodPut,
			fmt.Sprintf(`=~/backup/%s_\d+\z`, strings.Replace(t.Name(), "/", "-", -1)),
			httpmock.NewStringResponder(http.StatusOK, ""),
		)
		err = runner.Reconcile(controller, e)
		require.NoError(t, err)

		updated, err := runner.Client.EtcdV1alpha2().EtcdClusters(e.Namespace).Get(context.TODO(), e.Name, metav1.GetOptions{})
		require.NoError(t, err)
		runner.AssertUpdateAction(t, "status", updated)
		runner.AssertNoUnexpectedAction(t)

		updatedEC, err := runner.Client.EtcdV1alpha2().EtcdClusters(cluster.Namespace).Get(context.TODO(), cluster.Name, metav1.GetOptions{})
		require.NoError(t, err)

		assert.NotNil(t, updatedEC.Status.Backup)
		assert.True(t, updatedEC.Status.Backup.Succeeded)
		assert.Len(t, updatedEC.Status.Backup.History, 1)
		assert.Equal(t, updatedEC.Status.Backup.LastSucceededTime, updatedEC.Status.Backup.History[0].ExecuteTime)
	})

	t.Run("MinIO_Rotate", func(t *testing.T) {
		t.Parallel()

		runner := controllertest.NewTestRunner()
		etcdMockCluster := NewMockCluster()
		etcdMockMaintenance := NewMockMaintenance()
		mockOpt := &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance}
		transport := httpmock.NewMockTransport()
		controller, err := NewEtcdController(
			runner.SharedInformerFactory,
			runner.CoreSharedInformerFactory,
			runner.CoreClient,
			runner.Client,
			nil,
			"cluster.local",
			false,
			transport,
			mockOpt,
		)
		require.NoError(t, err)

		minIOService, minIOSecret := minIOFixtures()
		runner.RegisterFixtures(minIOService, minIOSecret)

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
		cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(runner)
		for _, v := range cluster.AllMembers() {
			runner.RegisterFixtures(k8sfactory.PodFactory(v.Pod, k8sfactory.Ready, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339))))
		}

		// Get bucket location
		transport.RegisterResponder(
			http.MethodGet,
			"/etcdcontroller/?location=",
			httpmock.NewStringResponder(http.StatusOK, `<LocationConstraint>us-west-2</LocationConstraint>`),
		)
		// Put object
		transport.RegisterResponder(
			http.MethodPut,
			fmt.Sprintf(`=~/backup/%s_\d+\z`, strings.Replace(t.Name(), "/", "-", -1)),
			httpmock.NewStringResponder(http.StatusOK, ""),
		)
		err = runner.Reconcile(controller, e)
		require.NoError(t, err)

		updated, err := runner.Client.EtcdV1alpha2().EtcdClusters(e.Namespace).Get(context.TODO(), e.Name, metav1.GetOptions{})
		require.NoError(t, err)
		runner.AssertUpdateAction(t, "status", updated)
		runner.AssertNoUnexpectedAction(t)
	})
}

func TestEtcdController_Restore(t *testing.T) {
	runner := controllertest.NewTestRunner()
	etcdMockCluster := NewMockCluster()
	etcdMockMaintenance := NewMockMaintenance()
	mockOpt := &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance}
	transport := httpmock.NewMockTransport()
	controller, err := NewEtcdController(
		runner.SharedInformerFactory,
		runner.CoreSharedInformerFactory,
		runner.CoreClient,
		runner.Client,
		nil,
		"cluster.local",
		false,
		transport,
		mockOpt,
	)
	require.NoError(t, err)

	e := etcd.Factory(nil,
		k8sfactory.Name(normalizeName(t.Name())),
		k8sfactory.Namespace(metav1.NamespaceDefault),
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
	cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil)
	cluster.registerBasicObjectOfEtcdCluster(runner)
	for _, v := range cluster.AllMembers() {
		v.Pod = k8sfactory.PodFactory(v.Pod, k8sfactory.Ready, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339)))

		v.Pod.Status.Phase = corev1.PodSucceeded
		runner.RegisterFixtures(v.Pod)
	}

	// Get bucket location
	transport.RegisterResponder(
		http.MethodGet,
		"/etcdcontroller/?location=",
		httpmock.NewStringResponder(http.StatusOK, `<LocationConstraint>us-west-2</LocationConstraint>`),
	)
	// Put object
	transport.RegisterResponder(
		http.MethodPut,
		fmt.Sprintf(`=~/backup/%s_\d+\z`, strings.Replace(t.Name(), "/", "-", -1)),
		httpmock.NewStringResponder(http.StatusOK, ""),
	)

	// Delete all members
	err = runner.Reconcile(controller, e)
	require.NoError(t, err)

	updated, err := runner.Client.EtcdV1alpha2().EtcdClusters(e.Namespace).Get(context.TODO(), e.Name, metav1.GetOptions{})
	require.NoError(t, err)
	runner.AssertUpdateAction(t, "status", updated)
	runner.AssertDeleteAction(t, k8sfactory.PodFactory(nil, k8sfactory.Namef("%s-1", e.Name), k8sfactory.Namespace(e.Namespace)))
	runner.AssertDeleteAction(t, k8sfactory.PodFactory(nil, k8sfactory.Namef("%s-2", e.Name), k8sfactory.Namespace(e.Namespace)))
	runner.AssertDeleteAction(t, k8sfactory.PodFactory(nil, k8sfactory.Namef("%s-3", e.Name), k8sfactory.Namespace(e.Namespace)))
	runner.AssertNoUnexpectedAction(t)

	updatedEC, err := runner.Client.EtcdV1alpha2().EtcdClusters(cluster.Namespace).Get(context.TODO(), cluster.Name, metav1.GetOptions{})
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

func (c *EtcdCluster) registerBasicObjectOfEtcdCluster(runner *controllertest.TestRunner) {
	ca, _ := c.CA()
	serverS, _ := c.ServerCertSecret()
	clientS, _ := c.ClientCertSecret()
	c.SetCASecret(ca)
	c.SetServerCertSecret(serverS)
	runner.RegisterFixtures(ca, serverS, clientS, c.DiscoveryService(), c.ClientService(), c.ServiceAccount(), c.EtcdRole(), c.EtcdRoleBinding())
}
