package e2eutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"go.etcd.io/etcd/v3/clientv3"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"

	etcdv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha2"
	proxyv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha2"
	clientset "go.f110.dev/heimdallr/operator/pkg/client/versioned"
)

func WaitForStatusOfEtcdClusterBecome(client clientset.Interface, ec *etcdv1alpha2.EtcdCluster, phase etcdv1alpha2.EtcdClusterPhase, timeout time.Duration) error {
	return wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		ec, err := client.EtcdV1alpha2().EtcdClusters(ec.Namespace).Get(context.TODO(), ec.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if ec.Status.Phase == phase {
			return true, nil
		}

		return false, nil
	})
}

func WaitForStatusOfProxyBecome(client clientset.Interface, p *proxyv1alpha2.Proxy, phase proxyv1alpha2.ProxyPhase, timeout time.Duration) error {
	return wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		pr, err := client.ProxyV1alpha2().Proxies(p.Namespace).Get(context.TODO(), p.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if pr.Status.Phase == phase {
			return true, nil
		}

		return false, nil
	})
}

func WaitForReadyOfProxy(client clientset.Interface, p *proxyv1alpha2.Proxy, timeout time.Duration) error {
	return wait.PollImmediate(5*time.Second, timeout, func() (bool, error) {
		pr, err := client.ProxyV1alpha2().Proxies(p.Namespace).Get(context.TODO(), p.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		return pr.Status.Ready, nil
	})
}

type EtcdClient struct {
	*clientv3.Client
	*portforward.PortForwarder
}

func (e *EtcdClient) Close() error {
	defer e.PortForwarder.Close()
	err := e.Client.Close()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func NewEtcdClient(coreClient kubernetes.Interface, cfg *rest.Config, ec *etcdv1alpha2.EtcdCluster) (*EtcdClient, error) {
	certSecret, err := coreClient.CoreV1().Secrets(ec.Namespace).Get(context.TODO(), ec.Status.ClientCertSecretName, metav1.GetOptions{})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	b, _ := pem.Decode(certSecret.Data["client.crt"])
	if b.Type != "CERTIFICATE" {
		return nil, xerrors.New("invalid client certificate")
	}
	clientCert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	b, _ = pem.Decode(certSecret.Data["client.key"])
	clientKey, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	b, _ = pem.Decode(certSecret.Data["ca.crt"])
	clientCACert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(clientCACert)

	svc, err := coreClient.CoreV1().Services(ec.Namespace).Get(context.TODO(), fmt.Sprintf("%s-client", ec.Name), metav1.GetOptions{})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	forwarder, err := PortForward(context.TODO(), cfg, coreClient, svc, "https")
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	ports, err := forwarder.GetPorts()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	port := ports[0].Local

	logConfig := zap.NewProductionConfig()
	logConfig.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
	clientCfg := clientv3.Config{
		Endpoints: []string{fmt.Sprintf("https://127.0.0.1:%d", port)},
		TLS: &tls.Config{
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{clientCert.Raw},
					PrivateKey:  clientKey,
				},
			},
			RootCAs:    caPool,
			ClientCAs:  caPool,
			ServerName: fmt.Sprintf("%s.%s.svc", svc.Name, svc.Namespace),
		},
		LogConfig: &logConfig,
	}
	client, err := clientv3.New(clientCfg)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return &EtcdClient{Client: client, PortForwarder: forwarder}, nil
}
