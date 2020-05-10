package test

import (
	"fmt"
	"time"

	"github.com/onsi/ginkgo"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/f110/lagrangian-proxy/operator/e2e/e2eutil"
	"github.com/f110/lagrangian-proxy/operator/pkg/api/etcd"
	etcdv1alpha1 "github.com/f110/lagrangian-proxy/operator/pkg/api/etcd/v1alpha1"
	clientset "github.com/f110/lagrangian-proxy/operator/pkg/client/versioned"
)

var Config *rest.Config

var _ = ginkgo.Describe("[EtcdController] etcd-controller", func() {
	ginkgo.It("should start some pods", func() {
		client, err := clientset.NewForConfig(Config)
		if err != nil {
			Fail(err)
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
			Fail(err)
		}

		if err := e2eutil.WaitForStatusOfEtcdClusterBecome(client, etcdCluster, etcdv1alpha1.ClusterPhaseRunning, 10*time.Minute); err != nil {
			Fail(err)
		}

		kubeClient, err := kubernetes.NewForConfig(Config)
		if err != nil {
			Fail(err)
		}
		pods, err := kubeClient.CoreV1().Pods(etcdCluster.Namespace).List(metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", etcd.LabelNameClusterName, etcdCluster.Name)})
		if err != nil {
			Fail(err)
		}
		if len(pods.Items) != 3 {
			Failf("Pods is not enough or too much: %d", len(pods.Items))
		}

		newEC, err := client.EtcdV1alpha1().EtcdClusters(etcdCluster.Namespace).Get(etcdCluster.Name, metav1.GetOptions{})
		if err != nil {
			Fail(err)
		}
		if newEC.Status.Phase != etcdv1alpha1.ClusterPhaseRunning {
			Failf("EtcdCluster phase is not running: %v", newEC.Status.Phase)
		}
	})

	ginkgo.Context("when change version", func() {
		ginkgo.It("should update all pods", func() {
			client, err := clientset.NewForConfig(Config)
			if err != nil {
				Fail(err)
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
				Fail(err)
			}

			if err := e2eutil.WaitForStatusOfEtcdClusterBecome(client, etcdCluster, etcdv1alpha1.ClusterPhaseRunning, 10*time.Minute); err != nil {
				Fail(err)
			}

			etcdCluster, err = client.EtcdV1alpha1().EtcdClusters(etcdCluster.Namespace).Get(etcdCluster.Name, metav1.GetOptions{})
			if err != nil {
				Fail(err)
			}
			etcdCluster.Spec.Version = "v3.4.4"
			_, err = client.EtcdV1alpha1().EtcdClusters(etcdCluster.Namespace).Update(etcdCluster)
			if err != nil {
				Fail(err)
			}

			if err := e2eutil.WaitForStatusOfEtcdClusterBecome(client, etcdCluster, etcdv1alpha1.ClusterPhaseUpdating, 1*time.Minute); err != nil {
				Fail(err)
			}
			if err := e2eutil.WaitForStatusOfEtcdClusterBecome(client, etcdCluster, etcdv1alpha1.ClusterPhaseRunning, 10*time.Minute); err != nil {
				Fail(err)
			}

			kubeClient, err := kubernetes.NewForConfig(Config)
			if err != nil {
				Fail(err)
			}
			pods, err := kubeClient.CoreV1().Pods(etcdCluster.Namespace).List(metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", etcd.LabelNameClusterName, etcdCluster.Name)})
			if err != nil {
				Fail(err)
			}

			if len(pods.Items) != 3 {
				Failf("Pods is not enough or too much: %v", len(pods.Items))
			}
			for _, v := range pods.Items {
				if v.Labels[etcd.LabelNameEtcdVersion] != etcdCluster.Spec.Version {
					Fail("Pod is not upgraded: %v", v.Labels[etcd.LabelNameEtcdVersion])
				}
			}
		})
	})
})
