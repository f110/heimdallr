package test

import (
	"fmt"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"go.f110.dev/heimdallr/operator/e2e/e2eutil"
	. "go.f110.dev/heimdallr/operator/e2e/framework"
	"go.f110.dev/heimdallr/operator/pkg/api/etcd"
	etcdv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha1"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
)

var (
	RESTConfig *rest.Config
)

func TestEtcdController(t *testing.T) {
	t.Parallel()

	Describe(t, "EtcdController", func() {
		Context("creates a new cluster", func() {
			It("should create some pods", func() {
				client, err := clientset.NewForConfig(RESTConfig)
				if err != nil {
					t.Fatal(err)
				}

				etcdCluster := &etcdv1alpha1.EtcdCluster{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "create",
						Namespace: "default",
					},
					Spec: etcdv1alpha1.EtcdClusterSpec{
						Members: 3,
						Version: "v3.4.4",
					},
				}
				_, err = client.EtcdV1alpha1().EtcdClusters(etcdCluster.Namespace).Create(etcdCluster)
				if err != nil {
					t.Fatal(err)
				}

				if err := e2eutil.WaitForStatusOfEtcdClusterBecome(client, etcdCluster, etcdv1alpha1.ClusterPhaseRunning, 10*time.Minute); err != nil {
					t.Fatal(err)
				}

				kubeClient, err := kubernetes.NewForConfig(RESTConfig)
				if err != nil {
					t.Fatal(err)
				}
				pods, err := kubeClient.CoreV1().Pods(etcdCluster.Namespace).List(metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", etcd.LabelNameClusterName, etcdCluster.Name)})
				if err != nil {
					t.Fatal(err)
				}
				So(pods.Items, ShouldHaveLength, 3)

				newEC, err := client.EtcdV1alpha1().EtcdClusters(etcdCluster.Namespace).Get(etcdCluster.Name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				So(newEC.Status.Phase, ShouldEqual, etcdv1alpha1.ClusterPhaseRunning)
			})
		})

		Context("updates the cluster", func() {
			It("recreates all pods", func() {
				client, err := clientset.NewForConfig(RESTConfig)
				if err != nil {
					t.Fatal(err)
				}

				etcdCluster := &etcdv1alpha1.EtcdCluster{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "update",
						Namespace: "default",
					},
					Spec: etcdv1alpha1.EtcdClusterSpec{
						Members: 3,
						Version: "v3.4.3",
					},
				}
				etcdCluster, err = client.EtcdV1alpha1().EtcdClusters(etcdCluster.Namespace).Create(etcdCluster)
				if err != nil {
					t.Fatal(err)
				}

				if err := e2eutil.WaitForStatusOfEtcdClusterBecome(client, etcdCluster, etcdv1alpha1.ClusterPhaseRunning, 10*time.Minute); err != nil {
					t.Fatal(err)
				}

				etcdCluster, err = client.EtcdV1alpha1().EtcdClusters(etcdCluster.Namespace).Get(etcdCluster.Name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				etcdCluster.Spec.Version = "v3.4.4"
				_, err = client.EtcdV1alpha1().EtcdClusters(etcdCluster.Namespace).Update(etcdCluster)
				if err != nil {
					t.Fatal(err)
				}

				if err := e2eutil.WaitForStatusOfEtcdClusterBecome(client, etcdCluster, etcdv1alpha1.ClusterPhaseUpdating, 1*time.Minute); err != nil {
					t.Fatal(err)
				}
				if err := e2eutil.WaitForStatusOfEtcdClusterBecome(client, etcdCluster, etcdv1alpha1.ClusterPhaseRunning, 10*time.Minute); err != nil {
					t.Fatal(err)
				}

				kubeClient, err := kubernetes.NewForConfig(RESTConfig)
				if err != nil {
					t.Fatal(err)
				}
				pods, err := kubeClient.CoreV1().Pods(etcdCluster.Namespace).List(metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", etcd.LabelNameClusterName, etcdCluster.Name)})
				if err != nil {
					t.Fatal(err)
				}

				So(pods.Items, ShouldHaveLength, 3)
				for _, v := range pods.Items {
					So(v.Labels[etcd.LabelNameEtcdVersion], ShouldEqual, etcdCluster.Spec.Version)
				}
			})
		})
	})
}
