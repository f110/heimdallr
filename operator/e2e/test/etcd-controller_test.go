package test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/smartystreets/goconvey/convey"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"go.f110.dev/heimdallr/operator/e2e/e2eutil"
	"go.f110.dev/heimdallr/operator/e2e/framework"
	"go.f110.dev/heimdallr/operator/pkg/api/etcd"
	etcdv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha1"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
)

var (
	RESTConfig *rest.Config
)

func TestEtcdController(t *testing.T) {
	t.Parallel()

	framework.Describe(t, "EtcdController", func() {
		framework.Context("creates a new cluster", func() {
			framework.It("should create some pods", func() {
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
				_, err = client.EtcdV1alpha1().EtcdClusters(etcdCluster.Namespace).Create(context.TODO(), etcdCluster, metav1.CreateOptions{})
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
				pods, err := kubeClient.CoreV1().Pods(etcdCluster.Namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", etcd.LabelNameClusterName, etcdCluster.Name)})
				if err != nil {
					t.Fatal(err)
				}
				convey.So(pods.Items, convey.ShouldHaveLength, 3)

				newEC, err := client.EtcdV1alpha1().EtcdClusters(etcdCluster.Namespace).Get(context.TODO(), etcdCluster.Name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				convey.So(newEC.Status.Phase, convey.ShouldEqual, etcdv1alpha1.ClusterPhaseRunning)
			})
		})

		framework.Context("updates the cluster", func() {
			framework.It("recreates all pods", func() {
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
				etcdCluster, err = client.EtcdV1alpha1().EtcdClusters(etcdCluster.Namespace).Create(context.TODO(), etcdCluster, metav1.CreateOptions{})
				if err != nil {
					t.Fatal(err)
				}

				if err := e2eutil.WaitForStatusOfEtcdClusterBecome(client, etcdCluster, etcdv1alpha1.ClusterPhaseRunning, 10*time.Minute); err != nil {
					t.Fatal(err)
				}

				etcdCluster, err = client.EtcdV1alpha1().EtcdClusters(etcdCluster.Namespace).Get(context.TODO(), etcdCluster.Name, metav1.GetOptions{})
				if err != nil {
					t.Fatal(err)
				}
				etcdCluster.Spec.Version = "v3.4.4"
				_, err = client.EtcdV1alpha1().EtcdClusters(etcdCluster.Namespace).Update(context.TODO(), etcdCluster, metav1.UpdateOptions{})
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
				pods, err := kubeClient.CoreV1().Pods(etcdCluster.Namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", etcd.LabelNameClusterName, etcdCluster.Name)})
				if err != nil {
					t.Fatal(err)
				}

				convey.So(pods.Items, convey.ShouldHaveLength, 3)
				for _, v := range pods.Items {
					convey.So(v.Labels[etcd.LabelNameEtcdVersion], convey.ShouldEqual, etcdCluster.Spec.Version)
				}
			})
		})
	})
}
