package e2eutil

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	etcdv1alpha1 "github.com/f110/lagrangian-proxy/operator/pkg/api/etcd/v1alpha1"
	clientset "github.com/f110/lagrangian-proxy/operator/pkg/client/versioned"
)

func WaitForStatusOfEtcdClusterBecome(client clientset.Interface, ec *etcdv1alpha1.EtcdCluster, phase etcdv1alpha1.EtcdClusterPhase, timeout time.Duration) error {
	ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
	defer cancelFunc()

	t := time.Tick(5 * time.Second)
Wait:
	for {
		select {
		case <-t:
			ec, err := client.EtcdV1alpha1().EtcdClusters(ec.Namespace).Get(ec.Name, metav1.GetOptions{})
			if err != nil {
				continue
			}

			if ec.Status.Phase == phase {
				break Wait
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}
