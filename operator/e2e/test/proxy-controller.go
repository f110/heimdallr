package test

import (
	"fmt"
	"time"

	certmanagermetav1 "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/onsi/ginkgo"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/f110/lagrangian-proxy/operator/e2e/e2eutil"
	proxyv1 "github.com/f110/lagrangian-proxy/operator/pkg/api/proxy/v1"
	clientset "github.com/f110/lagrangian-proxy/operator/pkg/client/versioned"
	"github.com/f110/lagrangian-proxy/pkg/config"
)

var _ = ginkgo.Describe("[ProxyController] proxy-controller", func() {
	ginkgo.It("creates EtcdCluster", func() {
		client, err := clientset.NewForConfig(Config)
		if err != nil {
			Fail(err)
		}
		coreClient, err := kubernetes.NewForConfig(Config)
		if err != nil {
			Fail(err)
		}

		clientSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-client-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"client-secret": []byte("client-secret"),
			},
		}
		_, err = coreClient.CoreV1().Secrets(clientSecret.Namespace).Create(clientSecret)
		if err != nil {
			Fail(err)
		}

		proxy := &proxyv1.Proxy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "create",
				Namespace: "default",
			},
			Spec: proxyv1.ProxySpec{
				Version: "v0.5.0",
				Domain:  "e2e.f110.dev",
				IdentityProvider: proxyv1.IdentityProviderSpec{
					ClientId: "e2e",
					ClientSecretRef: proxyv1.SecretSelector{
						Name: clientSecret.Name,
						Key:  "client-secret",
					},
				},
				IssuerRef: certmanagermetav1.ObjectReference{
					Kind: "ClusterIssuer",
					Name: "self-signed",
				},
				Session: proxyv1.SessionSpec{
					Type: config.SessionTypeSecureCookie,
				},
			},
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
			Fail("EtcdCluster is not found")
		}

		_, err = coreClient.AppsV1().Deployments(proxy.Namespace).Get(fmt.Sprintf("%s-rpcserver", proxy.Name), metav1.GetOptions{})
		if err != nil && apierrors.IsNotFound(err) {
			Fail("Deployment of rpcserver is not found")
		}
		_, err = coreClient.AppsV1().Deployments(proxy.Namespace).Get(proxy.Name, metav1.GetOptions{})
		if err != nil && apierrors.IsNotFound(err) {
			Fail("Deployment of proxy is not found")
		}
	})
})
