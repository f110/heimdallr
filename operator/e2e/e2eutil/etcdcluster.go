package e2eutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.f110.dev/kubeproto/go/apis/metav1"
	"go.f110.dev/xerrors"
	"go.uber.org/zap"
	k8smetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"

	"go.f110.dev/heimdallr/pkg/k8s/api/etcdv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxyv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/client"
	"go.f110.dev/heimdallr/pkg/poll"
)

func WaitForStatusOfEtcdClusterBecome(client *client.Set, ec *etcdv1alpha2.EtcdCluster, phase etcdv1alpha2.EtcdClusterPhase, timeout time.Duration) error {
	return poll.PollImmediate(context.TODO(), 5*time.Second, timeout, func(ctx context.Context) (done bool, err error) {
		ec, err := client.EtcdV1alpha2.GetEtcdCluster(ctx, ec.Namespace, ec.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if ec.Status.Phase == phase {
			return true, nil
		}

		return false, nil
	})
}

func WaitForStatusOfProxyBecome(client *client.Set, p *proxyv1alpha2.Proxy, phase proxyv1alpha2.ProxyPhase, timeout time.Duration) error {
	return poll.PollImmediate(context.TODO(), 5*time.Second, timeout, func(ctx context.Context) (bool, error) {
		pr, err := client.ProxyV1alpha2.GetProxy(ctx, p.Namespace, p.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		if pr.Status.Phase == phase {
			return true, nil
		}

		return false, nil
	})
}

func WaitForReadyOfProxy(client *client.Set, p *proxyv1alpha2.Proxy, timeout time.Duration) error {
	return poll.PollImmediate(context.TODO(), 5*time.Second, timeout, func(ctx context.Context) (bool, error) {
		pr, err := client.ProxyV1alpha2.GetProxy(ctx, p.Namespace, p.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}

		return pr.Status.Ready, nil
	})
}

func WaitForBackup(client *client.Set, etcdCluster *etcdv1alpha2.EtcdCluster, after time.Time) error {
	return poll.PollImmediate(context.TODO(), 10*time.Second, 5*time.Minute, func(ctx context.Context) (bool, error) {
		e, err := client.EtcdV1alpha2.GetEtcdCluster(ctx, etcdCluster.Namespace, etcdCluster.Name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		if e.Status.Backup == nil {
			return false, nil
		}
		if e.Status.Backup.Succeeded && after.Before(e.Status.Backup.LastSucceededTime.Time()) {
			return true, nil
		}

		return false, nil
	})
}

func WaitForRestore(client *client.Set, etcdCluster *etcdv1alpha2.EtcdCluster, after time.Time) error {
	return poll.PollImmediate(context.TODO(), 10*time.Second, 2*time.Minute, func(ctx context.Context) (bool, error) {
		e, err := client.EtcdV1alpha2.GetEtcdCluster(ctx, etcdCluster.Namespace, etcdCluster.Name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		if e.Status.Restored != nil && !e.Status.Restored.Completed {
			return true, nil
		}

		return false, nil
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
		return xerrors.WithStack(err)
	}

	return nil
}

func NewEtcdClient(coreClient kubernetes.Interface, cfg *rest.Config, ec *etcdv1alpha2.EtcdCluster) (*EtcdClient, error) {
	certSecret, err := coreClient.CoreV1().Secrets(ec.Namespace).Get(context.TODO(), ec.Status.ClientCertSecretName, k8smetav1.GetOptions{})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	b, _ := pem.Decode(certSecret.Data["client.crt"])
	if b.Type != "CERTIFICATE" {
		return nil, xerrors.NewWithStack("invalid client certificate")
	}
	clientCert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	b, _ = pem.Decode(certSecret.Data["client.key"])
	clientKey, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	b, _ = pem.Decode(certSecret.Data["ca.crt"])
	clientCACert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(clientCACert)

	svc, err := coreClient.CoreV1().Services(ec.Namespace).Get(context.TODO(), fmt.Sprintf("%s-client", ec.Name), k8smetav1.GetOptions{})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	forwarder, err := PortForward(context.TODO(), cfg, coreClient, svc, "https")
	if err != nil {
		return nil, err
	}
	ports, err := forwarder.GetPorts()
	if err != nil {
		return nil, xerrors.WithStack(err)
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
		return nil, xerrors.WithStack(err)
	}

	return &EtcdClient{Client: client, PortForwarder: forwarder}, nil
}
