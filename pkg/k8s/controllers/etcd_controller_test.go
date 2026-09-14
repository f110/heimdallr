package controllers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.f110.dev/kubeproto/go/apis/corev1"
	"go.f110.dev/kubeproto/go/apis/metav1"

	"go.f110.dev/heimdallr/pkg/k8s/api/etcd"
	"go.f110.dev/heimdallr/pkg/k8s/api/etcdv1alpha2"
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
			&runner.CoreClient.Set,
			runner.Client.EtcdV1alpha2,
			runner.K8sCoreClient,
			nil,
			"cluster.local",
			false,
			nil,
			mockOpt,
		)

		e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.EtcdClusterPhasePending))
		err = runner.Reconcile(controller, e)
		require.NoError(t, err)

		updated := etcd.Factory(e, etcd.Phase(etcdv1alpha2.EtcdClusterPhasePending))
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
		updated = etcd.Factory(e, etcd.Phase(etcdv1alpha2.EtcdClusterPhaseInitializing))
		runner.AssertUpdateAction(t, "status", updated)
		runner.AssertNoUnexpectedAction(t)

		pod, err := runner.CoreClient.CoreV1.GetPod(context.TODO(), e.Namespace, fmt.Sprintf("%s-1", e.Name), metav1.GetOptions{})
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
			&runner.CoreClient.Set,
			runner.Client.EtcdV1alpha2,
			runner.K8sCoreClient,
			nil,
			"cluster.local",
			false,
			nil,
			mockOpt,
		)
		require.NoError(t, err)

		e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.EtcdClusterPhaseCreating))
		cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(runner)
		member := cluster.AllMembers()[0]
		member.Pod = k8sfactory.PodFactory(member.Pod, k8sfactory.Created, k8sfactory.Ready)
		runner.RegisterFixtures(member.Pod)

		err = runner.Reconcile(controller, e)
		require.NoError(t, err)

		updated := e.DeepCopy()
		updated.Status.ClientEndpoint = fmt.Sprintf("https://%s-client.%s.svc.cluster.local:2379", e.Name, e.Namespace)
		updated.Status.ClientCertSecretName = fmt.Sprintf("etcd-%s-client-cert", e.Name)
		runner.AssertCreateAction(t, k8sfactory.PodFactory(nil, k8sfactory.Namef("%s-2", e.Name), k8sfactory.Namespace(e.Namespace)))
		runner.AssertUpdateAction(t, "", k8sfactory.PodFactory(member.Pod, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339))))
		runner.AssertUpdateAction(t, "status", updated)
		runner.AssertNoUnexpectedAction(t)

		pods, err := runner.CoreClient.CoreV1.ListPod(context.TODO(), e.Namespace, metav1.ListOptions{LabelSelector: etcd.LabelNameClusterName + "=" + e.Name})
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
			&runner.CoreClient.Set,
			runner.Client.EtcdV1alpha2,
			runner.K8sCoreClient,
			nil,
			"cluster.local",
			false,
			nil,
			mockOpt,
		)
		require.NoError(t, err)

		e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.EtcdClusterPhaseRunning), etcd.Ready)
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

		pods, err := runner.CoreClient.CoreV1.ListPod(context.TODO(), e.Namespace, metav1.ListOptions{LabelSelector: etcd.LabelNameClusterName + "=" + e.Name})
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
				&runner.CoreClient.Set,
				runner.Client.EtcdV1alpha2,
				runner.K8sCoreClient,
				nil,
				"cluster.local",
				false,
				nil,
				mockOpt,
			)
			require.NoError(t, err)

			e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.EtcdClusterPhaseRunning), etcd.Ready)
			cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil)
			cluster.registerBasicObjectOfEtcdCluster(runner)
			for _, v := range cluster.AllMembers() {
				v.Pod.Labels[etcd.LabelNameEtcdVersion] = "v3.3.0"
				runner.RegisterFixtures(
					k8sfactory.PodFactory(v.Pod,
						k8sfactory.Created,
						k8sfactory.Ready,
						k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339)),
					),
				)
				etcdMockCluster.AddMember(&etcdserverpb.Member{Name: v.Pod.Name})
				e.Status.Members = append(e.Status.Members, etcdv1alpha2.MemberStatus{Name: v.Pod.Name})
			}
			tempMemberPod := cluster.newTemporaryMemberPodSpec(defaultEtcdVersion, []string{})
			runner.RegisterFixtures(k8sfactory.PodFactory(tempMemberPod, k8sfactory.Created, k8sfactory.Ready, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339))))

			err = runner.Reconcile(controller, e)
			require.NoError(t, err)

			updated := etcd.Factory(e, etcd.Phase(etcdv1alpha2.EtcdClusterPhaseUpdating), etcd.CreatedStatus)
			updated.Status.Members = updated.Status.Members[1:]
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
				&runner.CoreClient.Set,
				runner.Client.EtcdV1alpha2,
				runner.K8sCoreClient,
				nil,
				"cluster.local",
				false,
				nil,
				mockOpt,
			)
			require.NoError(t, err)

			e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.EtcdClusterPhaseUpdating), etcd.Ready)
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

			updated := etcd.Factory(e, etcd.Phase(etcdv1alpha2.EtcdClusterPhaseUpdating), etcd.CreatedStatus)
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
			&runner.CoreClient.Set,
			runner.Client.EtcdV1alpha2,
			runner.K8sCoreClient,
			nil,
			"cluster.local",
			false,
			nil,
			mockOpt,
		)
		require.NoError(t, err)

		e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.EtcdClusterPhaseUpdating), etcd.Ready)
		cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil)
		cluster.registerBasicObjectOfEtcdCluster(runner)
		for _, v := range cluster.AllMembers() {
			runner.RegisterFixtures(k8sfactory.PodFactory(v.Pod, k8sfactory.Created, k8sfactory.Ready, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339))))
			etcdMockCluster.AddMember(&etcdserverpb.Member{Name: v.Pod.Name})
			e.Status.Members = append(e.Status.Members, etcdv1alpha2.MemberStatus{Name: v.Pod.Name})
		}
		tempMemberPod := cluster.newTemporaryMemberPodSpec(defaultEtcdVersion, []string{})
		runner.RegisterFixtures(k8sfactory.PodFactory(tempMemberPod, k8sfactory.Created, k8sfactory.Ready, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339))))

		err = runner.Reconcile(controller, e)
		require.NoError(t, err)

		updated := etcd.Factory(e, etcd.Phase(etcdv1alpha2.EtcdClusterPhaseUpdating), etcd.CreatedStatus)
		runner.AssertDeleteAction(t, k8sfactory.PodFactory(nil, k8sfactory.Namef("%s-4", e.Name), k8sfactory.Namespace(e.Namespace)))
		runner.AssertUpdateAction(t, "status", updated)
		runner.AssertNoUnexpectedAction(t)
	})

	t.Run("Repair", func(t *testing.T) {
		t.Parallel()

		etcdContainerExited := func(object interface{}) {
			pod := object.(*corev1.Pod)
			statuses := make([]corev1.ContainerStatus, 0)
			for _, cs := range pod.Status.ContainerStatuses {
				if cs.Name == "etcd" {
					cs.Ready = false
					cs.State = &corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode: 1,
							Reason:   "Error",
						},
					}
				}
				statuses = append(statuses, cs)
			}
			pod.Status.ContainerStatuses = statuses
		}

		cases := []struct {
			Name        string
			PodMutation []k8sfactory.Trait
		}{
			{
				Name:        "PodSucceeded",
				PodMutation: []k8sfactory.Trait{k8sfactory.PodSucceeded},
			},
			{
				Name:        "PodFailed",
				PodMutation: []k8sfactory.Trait{k8sfactory.PodFailed},
			},
			{
				Name:        "EtcdPodError",
				PodMutation: []k8sfactory.Trait{etcdContainerExited},
			},
			{
				Name: "PodNotRunning",
				PodMutation: []k8sfactory.Trait{
					k8sfactory.NotReady,
					k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, ""),
					etcdContainerExited,
				},
			},
		}

		for _, tc := range cases {
			if tc.PodMutation == nil {
				t.Fatalf("PodMutation of %s is nil", tc.Name)
			}

			tc := tc
			t.Run(tc.Name, func(t *testing.T) {
				t.Parallel()

				runner := controllertest.NewTestRunner()
				etcdMockCluster := NewMockCluster()
				etcdMockMaintenance := NewMockMaintenance()
				mockOpt := &MockOption{Cluster: etcdMockCluster, Maintenance: etcdMockMaintenance}
				controller, err := NewEtcdController(
					runner.SharedInformerFactory,
					runner.CoreSharedInformerFactory,
					&runner.CoreClient.Set,
					runner.Client.EtcdV1alpha2,
					runner.K8sCoreClient,
					nil,
					"cluster.local",
					false,
					nil,
					mockOpt,
				)
				require.NoError(t, err)

				e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.EtcdClusterPhaseRunning), etcd.Ready)
				cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil)
				cluster.registerBasicObjectOfEtcdCluster(runner)
				for i, v := range cluster.AllMembers() {
					v.Pod = k8sfactory.PodFactory(v.Pod,
						k8sfactory.CreatedAt(time.Now().Add(-6*time.Minute)),
						k8sfactory.Ready,
						k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339)),
					)
					etcdMockCluster.AddMember(&etcdserverpb.Member{Name: v.Pod.Name})
					e.Status.Members = append(e.Status.Members, etcdv1alpha2.MemberStatus{Name: v.Pod.Name})

					if i == 0 {
						v.Pod = k8sfactory.PodFactory(v.Pod, tc.PodMutation...)
					}
				}
				for _, v := range cluster.AllMembers() {
					runner.RegisterFixtures(v.Pod)
				}

				err = runner.Reconcile(controller, e)
				require.NoError(t, err)

				updated := etcd.Factory(e, etcd.Phase(etcdv1alpha2.EtcdClusterPhaseDegrading), etcd.CreatedStatus)
				updated.Status.Members = updated.Status.Members[1:]
				runner.AssertDeleteAction(t, k8sfactory.PodFactory(nil, k8sfactory.Namef("%s-1", e.Name), k8sfactory.Namespace(e.Namespace)))
				runner.AssertUpdateAction(t, "status", updated)
				runner.AssertNoUnexpectedAction(t)
			})
		}
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
			&runner.CoreClient.Set,
			runner.Client.EtcdV1alpha2,
			runner.K8sCoreClient,
			nil,
			"cluster.local",
			false,
			nil,
			mockOpt,
		)
		require.NoError(t, err)

		e := etcd.Factory(etcdClusterBase,
			etcd.Phase(etcdv1alpha2.EtcdClusterPhaseRunning),
			etcd.Ready,
			etcd.Backup(30, 5),
			etcd.BackupToMinIO(
				"etcdcontroller",
				"/backup",
				false,
				"test",
				metav1.NamespaceDefault,
				&etcdv1alpha2.AWSCredentialSelector{
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

		updated := etcd.Factory(e, etcd.Phase(etcdv1alpha2.EtcdClusterPhaseInitializing), etcd.CreatedStatus)
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
			&runner.CoreClient.Set,
			runner.Client.EtcdV1alpha2,
			runner.K8sCoreClient,
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
			etcd.Phase(etcdv1alpha2.EtcdClusterPhaseRunning),
		)
		e.Spec.Backup = &etcdv1alpha2.BackupSpec{
			IntervalInSeconds: 30,
			Storage: &etcdv1alpha2.BackupStorageSpec{
				MinIO: &etcdv1alpha2.BackupStorageMinIOSpec{
					ServiceSelector: &etcdv1alpha2.ObjectSelector{Name: minIOService.Name, Namespace: minIOService.Namespace},
					CredentialSelector: &etcdv1alpha2.AWSCredentialSelector{
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
			runner.RegisterFixtures(k8sfactory.PodFactory(v.Pod, k8sfactory.Created, k8sfactory.Ready, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339))))
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

		updated, err := runner.Client.EtcdV1alpha2.GetEtcdCluster(context.Background(), e.Namespace, e.Name, metav1.GetOptions{})
		require.NoError(t, err)
		runner.AssertUpdateAction(t, "status", updated)
		runner.AssertNoUnexpectedAction(t)

		updatedEC, err := runner.Client.EtcdV1alpha2.GetEtcdCluster(context.Background(), cluster.Namespace, cluster.Name, metav1.GetOptions{})
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
			&runner.CoreClient.Set,
			runner.Client.EtcdV1alpha2,
			runner.K8sCoreClient,
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
			etcd.Phase(etcdv1alpha2.EtcdClusterPhaseRunning),
			etcd.Backup(30, 5),
			etcd.BackupToMinIO(
				"etcdcontroller",
				"/backup",
				false,
				minIOService.Name,
				minIOService.Namespace,
				&etcdv1alpha2.AWSCredentialSelector{
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
			runner.RegisterFixtures(k8sfactory.PodFactory(v.Pod, k8sfactory.Created, k8sfactory.Ready, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339))))
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

		updated, err := runner.Client.EtcdV1alpha2.GetEtcdCluster(context.Background(), e.Namespace, e.Name, metav1.GetOptions{})
		require.NoError(t, err)
		runner.AssertUpdateAction(t, "status", updated)
		runner.AssertNoUnexpectedAction(t)
	})
}

func TestEtcdController_RotateBackup(t *testing.T) {
	const bucket = "etcdcontroller"

	newFixture := func(t *testing.T, path string, maxBackups int) (*EtcdController, *EtcdCluster, *httpmock.MockTransport) {
		runner := controllertest.NewTestRunner()
		mockOpt := &MockOption{Cluster: NewMockCluster(), Maintenance: NewMockMaintenance()}
		transport := httpmock.NewMockTransport()
		controller, err := NewEtcdController(
			runner.SharedInformerFactory,
			runner.CoreSharedInformerFactory,
			&runner.CoreClient.Set,
			runner.Client.EtcdV1alpha2,
			runner.K8sCoreClient,
			nil,
			"cluster.local",
			false,
			transport,
			mockOpt,
		)
		require.NoError(t, err)

		minIOService, minIOSecret := minIOFixtures()
		runner.RegisterFixtures(minIOService, minIOSecret)

		e := etcd.Factory(nil,
			k8sfactory.Name(normalizeName(t.Name())),
			k8sfactory.Namespace(metav1.NamespaceDefault),
			k8sfactory.Created,
			etcd.Member(3),
			etcd.MemberStatus(nil),
			etcd.Phase(etcdv1alpha2.EtcdClusterPhaseRunning),
			etcd.Backup(30, maxBackups),
			etcd.BackupToMinIO(bucket, path, false, minIOService.Name, minIOService.Namespace, &etcdv1alpha2.AWSCredentialSelector{
				Name:               minIOSecret.Name,
				Namespace:          minIOSecret.Namespace,
				AccessKeyIDKey:     "accesskey",
				SecretAccessKeyKey: "secretkey",
			}),
		)

		// Get bucket location
		transport.RegisterResponder(
			http.MethodGet,
			fmt.Sprintf("/%s/?location=", bucket),
			httpmock.NewStringResponder(http.StatusOK, `<LocationConstraint>us-west-2</LocationConstraint>`),
		)

		return controller, NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil), transport
	}

	t.Run("NormalizePathPrefix", func(t *testing.T) {
		controller, cluster, transport := newFixture(t, "/backup", 2)

		var gotPrefix string
		transport.RegisterResponder(http.MethodGet, fmt.Sprintf("/%s/", bucket), func(req *http.Request) (*http.Response, error) {
			gotPrefix = req.URL.Query().Get("prefix")
			return httpmock.NewStringResponse(http.StatusOK, listObjectsResponse(bucket, gotPrefix)), nil
		})

		err := controller.doRotateBackup(context.Background(), cluster)
		require.NoError(t, err)

		// storeBackupFile trims the leading slash, so the rotation has to look up the same key space.
		assert.Equal(t, "backup/", gotPrefix)
	})

	t.Run("ReturnsListError", func(t *testing.T) {
		controller, cluster, transport := newFixture(t, "backup", 2)

		transport.RegisterResponder(http.MethodGet, fmt.Sprintf("/%s/", bucket), httpmock.NewStringResponder(http.StatusInternalServerError, ""))

		err := controller.doRotateBackup(context.Background(), cluster)
		require.Error(t, err)
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
		&runner.CoreClient.Set,
		runner.Client.EtcdV1alpha2,
		runner.K8sCoreClient,
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
			&etcdv1alpha2.AWSCredentialSelector{
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

		v.Pod.Status.Phase = corev1.PodPhaseSucceeded
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

	updated, err := runner.Client.EtcdV1alpha2.GetEtcdCluster(context.Background(), e.Namespace, e.Name, metav1.GetOptions{})
	require.NoError(t, err)
	runner.AssertUpdateAction(t, "status", updated)
	runner.AssertDeleteAction(t, k8sfactory.PodFactory(nil, k8sfactory.Namef("%s-1", e.Name), k8sfactory.Namespace(e.Namespace)))
	runner.AssertDeleteAction(t, k8sfactory.PodFactory(nil, k8sfactory.Namef("%s-2", e.Name), k8sfactory.Namespace(e.Namespace)))
	runner.AssertDeleteAction(t, k8sfactory.PodFactory(nil, k8sfactory.Namef("%s-3", e.Name), k8sfactory.Namespace(e.Namespace)))
	runner.AssertNoUnexpectedAction(t)

	updatedEC, err := runner.Client.EtcdV1alpha2.GetEtcdCluster(context.Background(), cluster.Namespace, cluster.Name, metav1.GetOptions{})
	require.NoError(t, err)

	require.NotNil(t, updatedEC.Status.Restored)
	assert.Equal(t, "backup/latest", updatedEC.Status.Restored.Path)
	assert.True(t, updatedEC.Status.Restored.Completed)
}

func TestEtcdController_DeleteMember(t *testing.T) {
	etcdClusterBase := etcd.Factory(nil,
		k8sfactory.Name(normalizeName(t.Name())),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.Created,
		etcd.Member(3),
		etcd.MemberStatus(nil),
	)

	peerURL := func(podIP string) string {
		return fmt.Sprintf("https://%s.%s.pod.cluster.local:%d", strings.ReplaceAll(podIP, ".", "-"), metav1.NamespaceDefault, EtcdPeerPort)
	}

	// An empty name means the member that hasn't joined the cluster yet.
	type etcdMember struct {
		Name  string
		PodIP string
	}
	cases := []struct {
		Name string
		// PodIP is the ip address of the Pod that is going to be deleted.
		PodIP string
		// Members is the members that belong to the cluster.
		Members []etcdMember
		// Remain is the ip addresses of the members that have to remain after deleting the member.
		Remain []string
	}{
		{
			Name:    "RemoveTheMemberOfThePod",
			PodIP:   "10.0.0.1",
			Members: []etcdMember{{"self", "10.0.0.1"}, {"other-2", "10.0.0.2"}, {"other-3", "10.0.0.3"}},
			Remain:  []string{"10.0.0.2", "10.0.0.3"},
		},
		{
			Name:    "RemoveTheMemberThatHasOutdatedPeerURL",
			PodIP:   "10.0.0.9",
			Members: []etcdMember{{"self", "10.0.0.1"}, {"other-2", "10.0.0.2"}},
			Remain:  []string{"10.0.0.2"},
		},
		{
			Name:    "KeepTheMemberThatHasSimilarAddress",
			PodIP:   "10.0.0.1",
			Members: []etcdMember{{"", "10.0.0.1"}, {"", "10.0.0.11"}},
			Remain:  []string{"10.0.0.11"},
		},
		{
			Name:    "KeepAllMembersIfThePodDoesNotHaveAddress",
			PodIP:   "",
			Members: []etcdMember{{"", "10.0.0.1"}, {"", "10.0.0.2"}},
			Remain:  []string{"10.0.0.1", "10.0.0.2"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			runner := controllertest.NewTestRunner()
			etcdMockCluster := NewMockCluster()
			mockOpt := &MockOption{Cluster: etcdMockCluster, Maintenance: NewMockMaintenance()}
			controller, err := NewEtcdController(
				runner.SharedInformerFactory,
				runner.CoreSharedInformerFactory,
				&runner.CoreClient.Set,
				runner.Client.EtcdV1alpha2,
				runner.K8sCoreClient,
				nil,
				"cluster.local",
				false,
				nil,
				mockOpt,
			)
			require.NoError(t, err)

			e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.EtcdClusterPhaseRunning), etcd.Ready)
			cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, mockOpt)
			cluster.registerBasicObjectOfEtcdCluster(runner)

			member := cluster.AllMembers()[0]
			member.Pod = k8sfactory.PodFactory(member.Pod, k8sfactory.Created, k8sfactory.Ready)
			member.Pod.Status.PodIP = tc.PodIP
			runner.RegisterFixtures(member.Pod)
			for _, v := range tc.Members {
				name := v.Name
				if name == "self" {
					name = member.Pod.Name
				}
				etcdMockCluster.AddMember(&etcdserverpb.Member{Name: name, PeerURLs: []string{peerURL(v.PodIP)}})
			}

			err = controller.deleteMember(context.Background(), cluster, member)
			require.NoError(t, err)

			res, err := etcdMockCluster.MemberList(context.Background())
			require.NoError(t, err)
			got := make([]string, 0, len(res.Members))
			for _, v := range res.Members {
				got = append(got, v.PeerURLs[0])
			}
			expect := make([]string, 0, len(tc.Remain))
			for _, v := range tc.Remain {
				expect = append(expect, peerURL(v))
			}
			assert.ElementsMatch(t, expect, got)
		})
	}
}

func TestEtcdController_RotateCertificate(t *testing.T) {
	etcdClusterBase := etcd.Factory(nil,
		k8sfactory.Name(normalizeName(t.Name())),
		k8sfactory.Namespace(metav1.NamespaceDefault),
		k8sfactory.Created,
		etcd.Member(3),
		etcd.MemberStatus(nil),
	)

	// The controller has to regenerate a certificate that expires within 90 days.
	issueExpiringCertificate := func(t *testing.T, c *EtcdCluster, dnsNames []string) (certPem, privateKeyPem []byte) {
		caPair, err := c.parseCASecret(c.caSecret)
		require.NoError(t, err)

		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		require.NoError(t, err)
		template := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: dnsNames[0]},
			NotBefore:    time.Now().AddDate(0, 0, -335),
			NotAfter:     time.Now().AddDate(0, 0, 30),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			DNSNames:     dnsNames,
		}
		b, err := x509.CreateCertificate(rand.Reader, template, caPair.Cert, &privateKey.PublicKey, caPair.PrivateKey)
		require.NoError(t, err)
		marshaledPrivateKey, err := x509.MarshalECPrivateKey(privateKey)
		require.NoError(t, err)

		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}),
			pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: marshaledPrivateKey})
	}

	parseCertificate := func(t *testing.T, certPem []byte) *x509.Certificate {
		block, _ := pem.Decode(certPem)
		require.NotNil(t, block)
		c, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		return c
	}

	newRunner := func(t *testing.T) (*controllertest.TestRunner, *EtcdController, *MockCluster) {
		runner := controllertest.NewTestRunner()
		etcdMockCluster := NewMockCluster()
		mockOpt := &MockOption{Cluster: etcdMockCluster, Maintenance: NewMockMaintenance()}
		controller, err := NewEtcdController(
			runner.SharedInformerFactory,
			runner.CoreSharedInformerFactory,
			&runner.CoreClient.Set,
			runner.Client.EtcdV1alpha2,
			runner.K8sCoreClient,
			nil,
			"cluster.local",
			false,
			nil,
			mockOpt,
		)
		require.NoError(t, err)

		return runner, controller, etcdMockCluster
	}

	t.Run("ServerCertificate", func(t *testing.T) {
		t.Parallel()

		runner, controller, etcdMockCluster := newRunner(t)

		e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.EtcdClusterPhaseRunning), etcd.Ready)
		cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil)
		ca, err := cluster.CA()
		require.NoError(t, err)
		cluster.SetCASecret(ca)
		certPem, privateKeyPem := issueExpiringCertificate(t, cluster, cluster.DNSNames())
		serverS := k8sfactory.SecretFactory(nil,
			k8sfactory.Name(cluster.ServerCertSecretName()),
			k8sfactory.Namespace(cluster.Namespace),
			k8sfactory.Data(serverCertSecretCertName, certPem),
			k8sfactory.Data(serverCertSecretPrivateKeyName, privateKeyPem),
		)
		cluster.SetServerCertSecret(serverS)
		clientS, err := cluster.ClientCertSecret()
		require.NoError(t, err)
		runner.RegisterFixtures(ca, serverS, clientS, cluster.DiscoveryService(), cluster.ClientService(), cluster.ServiceAccount(), cluster.EtcdRole(), cluster.EtcdRoleBinding())
		for _, v := range cluster.AllMembers() {
			runner.RegisterFixtures(k8sfactory.PodFactory(v.Pod, k8sfactory.Created, k8sfactory.Ready, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339))))
			etcdMockCluster.AddMember(&etcdserverpb.Member{Name: v.Pod.Name})
			e.Status.Members = append(e.Status.Members, etcdv1alpha2.MemberStatus{Name: v.Pod.Name})
		}

		err = runner.Reconcile(controller, e)
		require.NoError(t, err)

		got, err := runner.CoreClient.CoreV1.GetSecret(context.TODO(), e.Namespace, cluster.ServerCertSecretName(), metav1.GetOptions{})
		require.NoError(t, err)
		rotated := parseCertificate(t, got.Data[serverCertSecretCertName])
		assert.True(t, rotated.NotAfter.After(time.Now().AddDate(0, 0, 90)), "The server certificate is not rotated")
		assert.Equal(t, cluster.DNSNames(), rotated.DNSNames)
	})

	t.Run("ClientCertificate", func(t *testing.T) {
		t.Parallel()

		runner, controller, etcdMockCluster := newRunner(t)

		e := etcd.Factory(etcdClusterBase, etcd.Phase(etcdv1alpha2.EtcdClusterPhaseRunning), etcd.Ready)
		cluster := NewEtcdCluster(e, controller.clusterDomain, logger.Log, nil)
		ca, err := cluster.CA()
		require.NoError(t, err)
		cluster.SetCASecret(ca)
		serverS, err := cluster.ServerCertSecret()
		require.NoError(t, err)
		cluster.SetServerCertSecret(serverS)
		clientCertDNSName := fmt.Sprintf("%s.%s.%s.svc.%s", e.Name, cluster.ServerDiscoveryServiceName(), e.Namespace, cluster.ClusterDomain)
		certPem, privateKeyPem := issueExpiringCertificate(t, cluster, []string{clientCertDNSName})
		clientS := k8sfactory.SecretFactory(nil,
			k8sfactory.Name(cluster.ClientCertSecretName()),
			k8sfactory.Namespace(cluster.Namespace),
			k8sfactory.Data(clientCertSecretCACertName, ca.Data[caSecretCertName]),
			k8sfactory.Data(clientCertSecretCertName, certPem),
			k8sfactory.Data(clientCertSecretPrivateKeyName, privateKeyPem),
		)
		cluster.SetClientCertSecret(clientS)
		runner.RegisterFixtures(ca, serverS, clientS, cluster.DiscoveryService(), cluster.ClientService(), cluster.ServiceAccount(), cluster.EtcdRole(), cluster.EtcdRoleBinding())
		for _, v := range cluster.AllMembers() {
			runner.RegisterFixtures(k8sfactory.PodFactory(v.Pod, k8sfactory.Created, k8sfactory.Ready, k8sfactory.Annotation(etcd.PodAnnotationKeyRunningAt, runner.Now.Format(time.RFC3339))))
			etcdMockCluster.AddMember(&etcdserverpb.Member{Name: v.Pod.Name})
			e.Status.Members = append(e.Status.Members, etcdv1alpha2.MemberStatus{Name: v.Pod.Name})
		}

		err = runner.Reconcile(controller, e)
		require.NoError(t, err)

		got, err := runner.CoreClient.CoreV1.GetSecret(context.TODO(), e.Namespace, cluster.ClientCertSecretName(), metav1.GetOptions{})
		require.NoError(t, err)
		rotated := parseCertificate(t, got.Data[clientCertSecretCertName])
		assert.True(t, rotated.NotAfter.After(time.Now().AddDate(0, 0, 90)), "The client certificate is not rotated")
		assert.Equal(t, []string{clientCertDNSName}, rotated.DNSNames)
	})
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

// listObjectsResponse builds a ListObjectsV2 response that contains the given keys.
func listObjectsResponse(bucket, prefix string, keys ...string) string {
	var buf strings.Builder
	fmt.Fprintf(&buf, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>%s</Name><Prefix>%s</Prefix><KeyCount>%d</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>`, bucket, prefix, len(keys))
	for _, v := range keys {
		fmt.Fprintf(&buf, `<Contents><Key>%s</Key><LastModified>2026-09-14T16:00:00.000Z</LastModified><ETag>&quot;etag&quot;</ETag><Size>24608</Size><StorageClass>STANDARD</StorageClass></Contents>`, v)
	}
	buf.WriteString(`</ListBucketResult>`)
	return buf.String()
}
