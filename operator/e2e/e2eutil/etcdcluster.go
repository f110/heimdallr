package e2eutil

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	etcdv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha1"
	proxyv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha1"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
)

func WaitForStatusOfEtcdClusterBecome(client clientset.Interface, ec *etcdv1alpha1.EtcdCluster, phase etcdv1alpha1.EtcdClusterPhase, timeout time.Duration) error {
	return wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		ec, err := client.EtcdV1alpha1().EtcdClusters(ec.Namespace).Get(context.TODO(), ec.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if ec.Status.Phase == phase {
			return true, nil
		}

		return false, nil
	})
}

func WaitForStatusOfProxyBecome(client clientset.Interface, p *proxyv1alpha1.Proxy, phase proxyv1alpha1.ProxyPhase, timeout time.Duration) error {
	return wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		pr, err := client.ProxyV1alpha1().Proxies(p.Namespace).Get(context.TODO(), p.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if pr.Status.Phase == phase {
			return true, nil
		}

		return false, nil
	})
}

func WaitForReadyOfProxy(client clientset.Interface, p *proxyv1alpha1.Proxy, timeout time.Duration) error {
	return wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		pr, err := client.ProxyV1alpha1().Proxies(p.Namespace).Get(context.TODO(), p.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		return pr.Status.Ready, nil
	})
}
