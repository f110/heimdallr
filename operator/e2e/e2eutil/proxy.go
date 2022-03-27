package e2eutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/retry"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

	"go.f110.dev/heimdallr/pkg/cert"
	proxyv1alpha2 "go.f110.dev/heimdallr/pkg/k8s/api/proxy/v1alpha2"
	clientset "go.f110.dev/heimdallr/pkg/k8s/client/versioned"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/rpc"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
)

func DeployTestService(coreClient kubernetes.Interface, client clientset.Interface, proxy *proxyv1alpha2.Proxy, name string) (*proxyv1alpha2.Backend, error) {
	deployment, service, backend := makeTestService(proxy, name)
	_, err := coreClient.AppsV1().Deployments(deployment.Namespace).Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	_, err = coreClient.CoreV1().Services(service.Namespace).Create(context.TODO(), service, metav1.CreateOptions{})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	backend, err = client.ProxyV1alpha2().Backends(backend.Namespace).Create(context.TODO(), backend, metav1.CreateOptions{})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return backend, nil
}

func DeployDisableAuthnTestService(coreClient kubernetes.Interface, client clientset.Interface, proxy *proxyv1alpha2.Proxy, name string) (*proxyv1alpha2.Backend, error) {
	deployment, service, backend := makeTestService(proxy, name)
	_, err := coreClient.AppsV1().Deployments(deployment.Namespace).Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	_, err = coreClient.CoreV1().Services(service.Namespace).Create(context.TODO(), service, metav1.CreateOptions{})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	backend.Spec.DisableAuthn = true
	backend, err = client.ProxyV1alpha2().Backends(backend.Namespace).Create(context.TODO(), backend, metav1.CreateOptions{})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return backend, nil
}

func makeTestService(proxy *proxyv1alpha2.Proxy, name string) (*appsv1.Deployment, *corev1.Service, *proxyv1alpha2.Backend) {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: proxy.Namespace,
			Labels: map[string]string{
				"instance": proxy.Name,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "nginx"},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": "nginx", "name": name},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "nginx", Image: "nginx:1.17.10"},
					},
				},
			},
		},
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: proxy.Namespace,
			Labels:    map[string]string{"app": name},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "nginx", "name": name},
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 80},
			},
		},
	}
	backend := &proxyv1alpha2.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: proxy.Namespace,
			Labels:    proxy.Spec.BackendSelector.MatchLabels,
		},
		Spec: proxyv1alpha2.BackendSpec{
			Layer: "test",
			HTTP: []*proxyv1alpha2.BackendHTTPSpec{
				{
					Path: "/",
					ServiceSelector: &proxyv1alpha2.ServiceSelector{
						LabelSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{"app": name},
						},
						Port: "http",
					},
				},
			},

			Permissions: []proxyv1alpha2.Permission{
				{Name: "all", Locations: []proxyv1alpha2.Location{{Get: "/"}}},
			},
		},
	}

	return deployment, service, backend
}

type RPCClient struct {
	*rpcclient.ClientWithUserToken
	forwarder *portforward.PortForwarder
}

func EnsureExistingTestUser(rpcClient *RPCClient, id, role string) error {
	users, err := rpcClient.ListAllUser()
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	found := false
	for _, v := range users {
		if v.Id == id {
			found = true
			break
		}
	}
	if !found {
		if err := rpcClient.AddUser(id, role); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	return nil
}

func SetupClientCert(rpcClient *RPCClient, id string) (*tls.Certificate, error) {
	csr, privKey, err := cert.CreatePrivateKeyAndCertificateRequest(pkix.Name{CommonName: id}, nil)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	signedCert, err := rpcClient.NewCertByCSR(string(csr), rpcclient.CommonName(id))
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	clientCert := tls.Certificate{Certificate: [][]byte{signedCert.Certificate}, PrivateKey: privKey}

	return &clientCert, nil
}

func DialRPCServer(cfg *rest.Config, coreClient kubernetes.Interface, proxy *proxyv1alpha2.Proxy, id string) (*RPCClient, error) {
	rpcService, err := coreClient.CoreV1().Services(proxy.Namespace).Get(context.TODO(), fmt.Sprintf("%s-rpcserver", proxy.Name), metav1.GetOptions{})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	forwarder, err := PortForward(context.Background(), cfg, coreClient, rpcService, "h2")
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	// Not need checking return value of GetPorts.
	ports, _ := forwarder.GetPorts()

	caPool, err := CACertPool(coreClient, proxy)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	token, err := CreateJwtToken(coreClient, proxy, id)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	rpcClient, err := NewRPCClient(ports[0].Local, caPool, token)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return &RPCClient{ClientWithUserToken: rpcClient, forwarder: forwarder}, nil
}

func NewRPCClient(port uint16, caPool *x509.CertPool, token string) (*rpcclient.ClientWithUserToken, error) {
	cred := credentials.NewTLS(&tls.Config{ServerName: rpc.ServerHostname, RootCAs: caPool})
	conn, err := grpc.Dial(
		fmt.Sprintf("127.0.0.1:%d", port),
		grpc.WithTransportCredentials(cred),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: time.Second, PermitWithoutStream: true}),
		grpc.WithStreamInterceptor(retry.StreamClientInterceptor()),
		grpc.WithUnaryInterceptor(retry.UnaryClientInterceptor()),
	)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return rpcclient.NewClientWithUserToken(conn).WithToken(token), nil
}

func CreateJwtToken(coreClient kubernetes.Interface, proxy *proxyv1alpha2.Proxy, id string) (string, error) {
	signPrivKeyS, err := coreClient.CoreV1().Secrets(proxy.Namespace).Get(context.TODO(), proxy.Status.SigningPrivateKeySecretName, metav1.GetOptions{})
	if err != nil {
		return "", xerrors.Errorf(": %w", err)
	}

	b, _ := pem.Decode(signPrivKeyS.Data["privkey.pem"])
	privKey, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return "", xerrors.Errorf(": %w", err)
	}
	claim := jwt.NewWithClaims(jwt.SigningMethodES256, &jwt.StandardClaims{
		Id:        id,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
	})

	token, err := claim.SignedString(privKey)
	if err != nil {
		return "", xerrors.Errorf(": %w", err)
	}

	return token, nil
}

func CACertPool(coreClient kubernetes.Interface, proxy *proxyv1alpha2.Proxy) (*x509.CertPool, error) {
	caS, err := coreClient.CoreV1().Secrets(proxy.Namespace).Get(context.TODO(), proxy.Status.CASecretName, metav1.GetOptions{})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	b, _ := pem.Decode(caS.Data["ca.crt"])
	caCert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	return caPool, nil
}

func ProxyCertPool(coreClient kubernetes.Interface, proxy *proxyv1alpha2.Proxy) (*x509.CertPool, error) {
	caCertS, err := coreClient.CoreV1().Secrets(proxy.Namespace).Get(context.TODO(), fmt.Sprintf("%s-cert", proxy.Name), metav1.GetOptions{})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	pemB, _ := pem.Decode(caCertS.Data["ca.crt"])
	proxyCACert, err := x509.ParseCertificate(pemB.Bytes)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	proxyCertPool := x509.NewCertPool()
	proxyCertPool.AddCert(proxyCACert)

	return proxyCertPool, nil
}

func PortForward(ctx context.Context, cfg *rest.Config, coreClient kubernetes.Interface, svc *corev1.Service, portName string) (*portforward.PortForwarder, error) {
	var port int32 = -1
	for _, v := range svc.Spec.Ports {
		if v.Name == portName {
			port = v.TargetPort.IntVal
			break
		}
	}
	if port == -1 {
		return nil, xerrors.Errorf("%s is not found", portName)
	}

	selector := labels.SelectorFromSet(svc.Spec.Selector)
	podList, err := coreClient.CoreV1().Pods(svc.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector.String()})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	var pod *corev1.Pod
	for i, v := range podList.Items {
		if v.Status.Phase == corev1.PodRunning {
			pod = &podList.Items[i]
			break
		}
	}
	if pod == nil {
		return nil, xerrors.New("all pods are not running yet")
	}

	req := coreClient.CoreV1().RESTClient().Post().Resource("pods").Namespace(svc.Namespace).Name(pod.Name).SubResource("portforward")
	transport, upgrader, err := spdy.RoundTripperFor(cfg)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, req.URL())

	readyCh := make(chan struct{})
	pf, err := portforward.New(dialer, []string{fmt.Sprintf(":%d", port)}, ctx.Done(), readyCh, nil, nil)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	go func() {
		err := pf.ForwardPorts()
		if err != nil {
			switch v := err.(type) {
			case *apierrors.StatusError:
				logger.Log.Debug("Status error", zap.Any("err", v))
			}
		}
	}()

	select {
	case <-readyCh:
	case <-time.After(5 * time.Second):
		return nil, xerrors.New("timeout")
	}

	ports, err := pf.GetPorts()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if len(ports) != 1 {
		return nil, xerrors.New("GetPorts returns zero or more than two ports. This is a suspicious behavior.")
	}

	return pf, nil
}
