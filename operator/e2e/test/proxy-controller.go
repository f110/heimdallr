package test

import (
	"fmt"
	"time"

	"github.com/onsi/ginkgo"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/f110/lagrangian-proxy/operator/e2e/e2eutil"
	proxyv1 "github.com/f110/lagrangian-proxy/operator/pkg/api/proxy/v1"
	clientset "github.com/f110/lagrangian-proxy/operator/pkg/client/versioned"
)

var _ = ginkgo.Describe("[ProxyController] proxy-controller", func() {
	ginkgo.It("creates EtcdCluster", func() {
		client, err := clientset.NewForConfig(Config)
		if err != nil {
			Fail(err)
		}

		proxy := &proxyv1.Proxy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "create",
				Namespace: "default",
			},
			Spec: proxyv1.ProxySpec{},
		}

		_, err = client.ProxyV1().Proxies(proxy.Namespace).Create(proxy)
		if err != nil {
			Fail(err)
		}

		if err := e2eutil.WaitForStatusOfProxyBecome(client, proxy, proxyv1.ProxyPhaseRunning, 10*time.Minute); err != nil {
			Fail(err)
		}

		_, err = client.EtcdV1alpha1().EtcdClusters(proxy.Namespace).Get(fmt.Sprintf("%s-datastore", proxy.Name), metav1.GetOptions{})
		if err != nil && apierrors.IsNotFound(err) {
			Fail("")
		}
	})
})
