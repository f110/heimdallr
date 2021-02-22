package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/smartystreets/goconvey/convey"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"go.f110.dev/heimdallr/operator/e2e/e2eutil"
	"go.f110.dev/heimdallr/operator/e2e/framework"
	"go.f110.dev/heimdallr/operator/pkg/api/etcd"
	etcdv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha2"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
	"go.f110.dev/heimdallr/pkg/k8s/kind"
	"go.f110.dev/heimdallr/pkg/poll"
)

var (
	RESTConfig *rest.Config
)

func TestEtcdController(t *testing.T) {
	t.Parallel()

	framework.Describe(t, "EtcdController", func() {
		framework.Context("creates a new cluster", func() {
			framework.Context("with PersistentVolumeClaim", func() {
				framework.It("should create some pods with PersistentVolume", func() {
					client, err := clientset.NewForConfig(RESTConfig)
					if err != nil {
						t.Fatal(err)
					}

					etcdCluster := &etcdv1alpha2.EtcdCluster{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "pvc",
							Namespace: "default",
						},
						Spec: etcdv1alpha2.EtcdClusterSpec{
							Members:      3,
							Version:      "v3.4.4",
							AntiAffinity: true,
							VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{
								Spec: corev1.PersistentVolumeClaimSpec{
									AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
									Resources: corev1.ResourceRequirements{
										Requests: corev1.ResourceList{
											"storage": resource.MustParse("1Gi"),
										},
									},
								},
							},
						},
					}
					_, err = client.EtcdV1alpha2().EtcdClusters(etcdCluster.Namespace).Create(context.TODO(), etcdCluster, metav1.CreateOptions{})
					if err != nil {
						t.Fatal(err)
					}

					if err := e2eutil.WaitForStatusOfEtcdClusterBecome(client, etcdCluster, etcdv1alpha2.ClusterPhaseRunning, 10*time.Minute); err != nil {
						t.Fatal(err)
					}

					kubeClient, err := kubernetes.NewForConfig(RESTConfig)
					if err != nil {
						t.Fatal(err)
					}
					pods, err := kubeClient.CoreV1().Pods(etcdCluster.Namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", etcd.LabelNameClusterName, etcdCluster.Name)})
					if err != nil {
						t.Fatal(err)
					}
					convey.So(pods.Items, convey.ShouldHaveLength, 3)
				Item:
					for _, pod := range pods.Items {
						for _, vol := range pod.Spec.Volumes {
							if vol.Name == "data" {
								convey.So(vol.PersistentVolumeClaim, convey.ShouldNotBeNil)
								continue Item
							}
						}

						t.Fatal("Data volume does not attached")
					}

					newEC, err := client.EtcdV1alpha2().EtcdClusters(etcdCluster.Namespace).Get(context.TODO(), etcdCluster.Name, metav1.GetOptions{})
					if err != nil {
						t.Fatal(err)
					}
					convey.So(newEC.Status.Phase, convey.ShouldEqual, etcdv1alpha2.ClusterPhaseRunning)

					if err := client.EtcdV1alpha2().EtcdClusters(etcdCluster.Namespace).Delete(context.TODO(), etcdCluster.Name, metav1.DeleteOptions{}); err != nil {
						t.Fatal(err)
					}
				})
			})

			framework.Context("with EmptyDir", func() {
				framework.It("should create some pods", func() {
					client, err := clientset.NewForConfig(RESTConfig)
					if err != nil {
						t.Fatal(err)
					}

					etcdCluster := &etcdv1alpha2.EtcdCluster{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "create",
							Namespace: "default",
						},
						Spec: etcdv1alpha2.EtcdClusterSpec{
							Members:      3,
							Version:      "v3.4.4",
							AntiAffinity: true,
						},
					}
					_, err = client.EtcdV1alpha2().EtcdClusters(etcdCluster.Namespace).Create(context.TODO(), etcdCluster, metav1.CreateOptions{})
					if err != nil {
						t.Fatal(err)
					}

					if err := e2eutil.WaitForStatusOfEtcdClusterBecome(client, etcdCluster, etcdv1alpha2.ClusterPhaseRunning, 10*time.Minute); err != nil {
						t.Fatal(err)
					}

					kubeClient, err := kubernetes.NewForConfig(RESTConfig)
					if err != nil {
						t.Fatal(err)
					}
					pods, err := kubeClient.CoreV1().Pods(etcdCluster.Namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", etcd.LabelNameClusterName, etcdCluster.Name)})
					if err != nil {
						t.Fatal(err)
					}
					convey.So(pods.Items, convey.ShouldHaveLength, 3)
				Item:
					for _, pod := range pods.Items {
						for _, vol := range pod.Spec.Volumes {
							if vol.Name == "data" {
								convey.So(vol.EmptyDir, convey.ShouldNotBeNil)
								continue Item
							}
						}

						t.Fatal("Data volume does not attached")
					}

					newEC, err := client.EtcdV1alpha2().EtcdClusters(etcdCluster.Namespace).Get(context.TODO(), etcdCluster.Name, metav1.GetOptions{})
					if err != nil {
						t.Fatal(err)
					}
					convey.So(newEC.Status.Phase, convey.ShouldEqual, etcdv1alpha2.ClusterPhaseRunning)

					if err := client.EtcdV1alpha2().EtcdClusters(etcdCluster.Namespace).Delete(context.TODO(), etcdCluster.Name, metav1.DeleteOptions{}); err != nil {
						t.Fatal(err)
					}
				})
			})
		})

		framework.Context("updates the cluster", func() {
			framework.It("recreates all pods", func() {
				client, err := clientset.NewForConfig(RESTConfig)
				if err != nil {
					t.Fatal(err)
				}

				etcdCluster := &etcdv1alpha2.EtcdCluster{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "update",
						Namespace: "default",
					},
					Spec: etcdv1alpha2.EtcdClusterSpec{
						Members: 3,
						Version: "v3.4.3",
					},
				}
				etcdCluster, err = client.EtcdV1alpha2().EtcdClusters(etcdCluster.Namespace).Create(context.TODO(), etcdCluster, metav1.CreateOptions{})
				if err != nil {
					t.Fatal(err)
				}

				if err := e2eutil.WaitForStatusOfEtcdClusterBecome(client, etcdCluster, etcdv1alpha2.ClusterPhaseRunning, 10*time.Minute); err != nil {
					t.Fatal(err)
				}

				etcdCluster, err = client.EtcdV1alpha2().EtcdClusters(etcdCluster.Namespace).Get(context.TODO(), etcdCluster.Name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				etcdCluster.Spec.Version = "v3.4.4"
				_, err = client.EtcdV1alpha2().EtcdClusters(etcdCluster.Namespace).Update(context.TODO(), etcdCluster, metav1.UpdateOptions{})
				if err != nil {
					t.Fatal(err)
				}

				if err := e2eutil.WaitForStatusOfEtcdClusterBecome(client, etcdCluster, etcdv1alpha2.ClusterPhaseUpdating, 1*time.Minute); err != nil {
					t.Fatal(err)
				}
				if err := e2eutil.WaitForStatusOfEtcdClusterBecome(client, etcdCluster, etcdv1alpha2.ClusterPhaseRunning, 10*time.Minute); err != nil {
					t.Fatal(err)
				}

				kubeClient, err := kubernetes.NewForConfig(RESTConfig)
				if err != nil {
					t.Fatal(err)
				}
				pods, err := kubeClient.CoreV1().Pods(etcdCluster.Namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", etcd.LabelNameClusterName, etcdCluster.Name)})
				if err != nil {
					t.Fatal(err)
				}

				convey.So(pods.Items, convey.ShouldHaveLength, 3)
				for _, v := range pods.Items {
					convey.So(v.Labels[etcd.LabelNameEtcdVersion], convey.ShouldEqual, etcdCluster.Spec.Version)
				}

				if err := client.EtcdV1alpha2().EtcdClusters(etcdCluster.Namespace).Delete(context.TODO(), etcdCluster.Name, metav1.DeleteOptions{}); err != nil {
					t.Fatal(err)
				}
			})
		})

		framework.Context("restore from backup", func() {
			framework.It("should have same data", func() {
				client, err := clientset.NewForConfig(RESTConfig)
				if err != nil {
					t.Fatal(err)
				}
				kubeClient, err := kubernetes.NewForConfig(RESTConfig)
				if err != nil {
					t.Fatal(err)
				}

				etcdCluster := &etcdv1alpha2.EtcdCluster{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "restore",
						Namespace: metav1.NamespaceDefault,
					},
					Spec: etcdv1alpha2.EtcdClusterSpec{
						Members:      3,
						Version:      "v3.4.4",
						AntiAffinity: true,
						Backup: &etcdv1alpha2.BackupSpec{
							IntervalInSecond: 60,
							MaxBackups:       5,
							Storage: etcdv1alpha2.BackupStorageSpec{
								MinIO: &etcdv1alpha2.BackupStorageMinIOSpec{
									Bucket: kind.MinIOBucketName,
									Path:   "restore-test",
									ServiceSelector: etcdv1alpha2.ObjectSelector{
										Name:      "minio",
										Namespace: metav1.NamespaceDefault,
									},
									CredentialSelector: etcdv1alpha2.AWSCredentialSelector{
										Name:               "minio-token",
										Namespace:          metav1.NamespaceDefault,
										AccessKeyIDKey:     "accesskey",
										SecretAccessKeyKey: "secretkey",
									},
								},
							},
						},
					},
				}
				_, err = client.EtcdV1alpha2().EtcdClusters(etcdCluster.Namespace).Create(context.TODO(), etcdCluster, metav1.CreateOptions{})
				if err != nil {
					t.Fatal(err)
				}
				if err := e2eutil.WaitForStatusOfEtcdClusterBecome(client, etcdCluster, etcdv1alpha2.ClusterPhaseRunning, 10*time.Minute); err != nil {
					t.Fatal(err)
				}

				const testDataKey = "e2e-test-data"
				etcdCluster, err = client.EtcdV1alpha2().EtcdClusters(etcdCluster.Namespace).Get(context.TODO(), etcdCluster.Name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				ecClient, err := e2eutil.NewEtcdClient(kubeClient, RESTConfig, etcdCluster)
				if err != nil {
					t.Fatal(err)
				}
				_, err = ecClient.Put(context.TODO(), testDataKey, "ok-test")
				if err != nil {
					t.Fatal(err)
				}
				if err := ecClient.Close(); err != nil {
					t.Fatal(err)
				}
				dataPutTime := time.Now()

				err = poll.PollImmediate(context.TODO(), 10*time.Second, 2*time.Minute, func(ctx context.Context) (bool, error) {
					e, err := client.EtcdV1alpha2().EtcdClusters(etcdCluster.Namespace).Get(ctx, etcdCluster.Name, metav1.GetOptions{})
					if err != nil {
						return false, nil
					}
					if e.Status.Backup == nil {
						return false, nil
					}
					if e.Status.Backup.Succeeded && dataPutTime.Before(e.Status.Backup.LastSucceededTime.Time) {
						return true, nil
					}

					return false, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				etcdCluster, err = client.EtcdV1alpha2().EtcdClusters(etcdCluster.Namespace).Get(context.TODO(), etcdCluster.Name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}

				for _, v := range etcdCluster.Status.Members {
					err = kubeClient.CoreV1().Pods(etcdCluster.Namespace).Delete(context.TODO(), v.PodName, metav1.DeleteOptions{})
					if err != nil {
						t.Fatal(err)
					}
				}

				err = poll.PollImmediate(context.TODO(), 10*time.Second, 3*time.Minute, func(ctx context.Context) (bool, error) {
					e, err := client.EtcdV1alpha2().EtcdClusters(etcdCluster.Namespace).Get(ctx, etcdCluster.Name, metav1.GetOptions{})
					if err != nil {
						return false, nil
					}
					if e.Status.Restored != nil && !e.Status.Restored.Completed {
						return true, nil
					}

					return false, nil
				})
				if err := e2eutil.WaitForStatusOfEtcdClusterBecome(client, etcdCluster, etcdv1alpha2.ClusterPhaseRunning, 10*time.Minute); err != nil {
					t.Fatal(err)
				}

				ecClient, err = e2eutil.NewEtcdClient(kubeClient, RESTConfig, etcdCluster)
				if err != nil {
					t.Fatal(err)
				}
				res, err := ecClient.Get(context.TODO(), testDataKey)
				if err != nil {
					t.Fatal(err)
				}
				convey.So(res.Count, convey.ShouldEqual, 1)
				convey.So(string(res.Kvs[0].Value), convey.ShouldEqual, "ok-test")
			})
		})
	})
}
