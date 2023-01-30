package framework

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	certmanagermetav1 "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"go.f110.dev/heimdallr/operator/e2e/e2eutil"
	"go.f110.dev/heimdallr/pkg/k8s/api/etcd"
	"go.f110.dev/heimdallr/pkg/k8s/api/etcdv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxy"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxyv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/client"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
	"go.f110.dev/heimdallr/pkg/testing/btesting"
)

var Config = &ConfigStruct{}

var ProxyBase = proxy.Factory(&proxyv1alpha2.Proxy{
	Spec: proxyv1alpha2.ProxySpec{
		Development: true,
		Domain:      "e2e.f110.dev",
		Replicas:    3,
		CertificateAuthority: &proxyv1alpha2.CertificateAuthoritySpec{
			Local: &proxyv1alpha2.LocalCertificateAuthoritySpec{
				Name: "e2e",
			},
		},
		BackendSelector: &proxyv1alpha2.LabelSelector{
			LabelSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"instance": "e2e"},
			},
		},
		RoleSelector: &proxyv1alpha2.LabelSelector{
			LabelSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"instance": "e2e"},
			},
		},
		IdentityProvider: proxyv1alpha2.IdentityProviderSpec{
			Provider: "google",
			ClientId: "e2e",
		},
		IssuerRef: certmanagermetav1.ObjectReference{
			Kind: "ClusterIssuer",
			Name: "self-signed",
		},
	},
}, k8sfactory.Name("e2e"), k8sfactory.Namespace(metav1.NamespaceDefault), proxy.EtcdDataStore, proxy.CookieSession)

var EtcdClusterBase = etcd.Factory(nil,
	k8sfactory.Namespace(metav1.NamespaceDefault),
	etcd.Version("v3.4.3"),
	etcd.HighAvailability,
)

type ConfigStruct struct {
	RandomSeed         int64
	ProxyVersion       string
	CRDDir             string
	ClusterVersion     string
	Verbose            bool
	KindFile           string
	OperatorImageFile  string
	ProxyImageFile     string
	RPCImageFile       string
	DashboardImageFile string
	SidecarImageFile   string
	BuildVersion       string
	AllInOneManifest   string
	Step               bool
	Retain             bool
}

func Flags(fs *flag.FlagSet) {
	fs.Int64Var(&Config.RandomSeed, "random-seed", time.Now().Unix(), "Random seed")
	fs.StringVar(&Config.ProxyVersion, "proxy.version", "", "Proxy version")
	fs.StringVar(&Config.CRDDir, "crd", "", "CRD files")
	fs.BoolVar(&Config.Verbose, "verbose", false, "View controller's log")
	fs.StringVar(&Config.ClusterVersion, "cluster-version", "v0.18.8", "Kubernetes cluster version")
	fs.StringVar(&Config.KindFile, "kind-file", "", "Kind executable file path")
	fs.StringVar(&Config.OperatorImageFile, "operator-image-file", "", "Operator image file")
	fs.StringVar(&Config.ProxyImageFile, "proxy-image-file", "", "Proxy image file")
	fs.StringVar(&Config.RPCImageFile, "rpc-image-file", "", "RPC image file")
	fs.StringVar(&Config.DashboardImageFile, "dashboard-image-file", "", "Dashboard image file")
	fs.StringVar(&Config.SidecarImageFile, "sidecar-image-file", "", "Sidecar image file")
	fs.StringVar(&Config.AllInOneManifest, "all-in-one-manifest", "", "Manifest file for operator")
	fs.StringVar(&Config.BuildVersion, "build-version", "", "Version string")
	fs.BoolVar(&Config.Step, "step", false, "Step execution")
	fs.BoolVar(&Config.Retain, "retain", false, "Do not delete cluster after test")
}

type Framework struct {
	*btesting.BehaviorDriven

	Proxy        *Proxy
	EtcdClusters *EtcdClusters

	client     *client.Set
	coreClient *kubernetes.Clientset
}

func New(t *testing.T, conf *rest.Config) *Framework {
	c, err := client.NewSet(conf)
	if err != nil {
		t.Fatal(err)
	}
	coreClient, err := kubernetes.NewForConfig(conf)
	if err != nil {
		t.Fatal(err)
	}

	return &Framework{
		BehaviorDriven: btesting.New(t, "", Config.Step),
		Proxy:          &Proxy{restConfig: conf, coreClient: coreClient, client: c},
		EtcdClusters: &EtcdClusters{
			restConfig: conf,
			coreClient: coreClient,
			client:     c,
			clusters:   make(map[string]*etcdv1alpha2.EtcdCluster),
		},
		client:     c,
		coreClient: coreClient,
	}
}

func (f *Framework) Execute() {
	f.BehaviorDriven.Execute("")
}

func (f *Framework) Client() *client.Set {
	return f.client
}

func (f *Framework) CoreClient() *kubernetes.Clientset {
	return f.coreClient
}

type Proxy struct {
	restConfig *rest.Config
	client     *client.Set
	coreClient *kubernetes.Clientset

	proxy          *proxyv1alpha2.Proxy
	userClientCert *tls.Certificate
	Backend        *proxyv1alpha2.Backend
}

func (p *Proxy) Setup(m *btesting.Matcher, testUserId string) bool {
	clientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-client-secret",
			Namespace: "default",
		},
		Data: map[string][]byte{
			"client-secret": []byte("client-secret"),
		},
	}
	_, err := p.coreClient.CoreV1().Secrets(clientSecret.Namespace).Create(context.TODO(), clientSecret, metav1.CreateOptions{})
	m.NoError(err)

	proxySpec := proxy.Factory(ProxyBase,
		proxy.ClientSecret("e2e-client-secret", "client-secret"),
		proxy.RootUsers([]string{testUserId}),
		proxy.Version(Config.ProxyVersion),
	)
	p.proxy = proxySpec
	testServiceBackend, err := e2eutil.DeployTestService(p.coreClient, p.client, proxySpec, "hello")
	m.NoError(err)
	p.Backend = testServiceBackend
	disableAuthnTestBackend, err := e2eutil.DeployDisableAuthnTestService(p.coreClient, p.client, proxySpec, "disauth")
	m.NoError(err)
	role := &proxyv1alpha2.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "admin",
			Namespace: proxySpec.Namespace,
			Labels:    proxySpec.Spec.RoleSelector.LabelSelector.MatchLabels,
		},
		Spec: proxyv1alpha2.RoleSpec{
			Title:       "administrator",
			Description: "admin",
		},
	}
	role, err = p.client.ProxyV1alpha2.CreateRole(context.TODO(), role, metav1.CreateOptions{})
	m.NoError(err)
	roleBinding := &proxyv1alpha2.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "admin",
			Namespace: proxySpec.Namespace,
		},
		RoleRef: proxyv1alpha2.RoleRef{
			Name:      "admin",
			Namespace: proxySpec.Namespace,
		},
		Subjects: []proxyv1alpha2.Subject{
			{Kind: "Backend", Name: fmt.Sprintf("%s-dashboard", proxySpec.Name), Namespace: proxySpec.Namespace, Permission: "all"},
			{Kind: "Backend", Name: testServiceBackend.Name, Namespace: proxySpec.Namespace, Permission: "all"},
			{Kind: "Backend", Name: disableAuthnTestBackend.Name, Namespace: proxySpec.Namespace, Permission: "all"},
		},
	}
	_, err = p.client.ProxyV1alpha2.CreateRoleBinding(context.TODO(), roleBinding, metav1.CreateOptions{})
	m.NoError(err)

	_, err = p.client.ProxyV1alpha2.CreateProxy(context.TODO(), proxySpec, metav1.CreateOptions{})
	m.NoError(err)

	m.NoError(e2eutil.WaitForStatusOfProxyBecome(p.client, proxySpec, proxyv1alpha2.ProxyPhaseRunning, 10*time.Minute))
	m.NoError(e2eutil.WaitForReadyOfProxy(p.client, proxySpec, 10*time.Minute))
	proxySpec, err = p.client.ProxyV1alpha2.GetProxy(context.TODO(), proxySpec.Namespace, proxySpec.Name, metav1.GetOptions{})
	m.NoError(err)

	rpcClient, err := e2eutil.DialRPCServer(p.restConfig, p.coreClient, proxySpec, testUserId)
	m.NoError(err)
	err = e2eutil.EnsureExistingTestUser(rpcClient, testUserId, role.Name)
	m.NoError(err)
	clientCert, err := e2eutil.SetupClientCert(rpcClient, testUserId)
	p.userClientCert = clientCert
	return m.Must(err)
}

func (p *Proxy) Agent(clientCert bool) *Agent {
	var cert *tls.Certificate
	if clientCert {
		cert = p.userClientCert
	}
	return &Agent{
		clientCert: cert,
		coreClient: p.coreClient,
		restConfig: p.restConfig,
		proxy:      p.proxy,
	}
}

type Agent struct {
	proxy      *proxyv1alpha2.Proxy
	clientCert *tls.Certificate

	restConfig *rest.Config
	coreClient *kubernetes.Clientset
}

func (a *Agent) Get(m *btesting.Matcher, backend *proxyv1alpha2.Backend, body io.Reader) bool {
	proxyCertPool, err := e2eutil.ProxyCertPool(a.coreClient, a.proxy)
	m.Must(err)

	proxyService, err := a.coreClient.CoreV1().Services(a.proxy.Namespace).Get(context.TODO(), fmt.Sprintf("%s", a.proxy.Name), metav1.GetOptions{})
	m.Must(err)
	forwarder, err := e2eutil.PortForward(context.Background(), a.restConfig, a.coreClient, proxyService, "https")
	m.Must(err)
	ports, err := forwarder.GetPorts()
	m.Must(err)
	port := ports[0].Local

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://127.0.0.1:%d", port), body)
	m.Must(err)
	if backend.Spec.Layer != "" {
		req.Host = fmt.Sprintf("%s.%s.%s", backend.Name, backend.Spec.Layer, a.proxy.Spec.Domain)
	} else {
		req.Host = fmt.Sprintf("%s.%s", backend.Name, a.proxy.Spec.Domain)
	}
	tlsConfig := &tls.Config{
		RootCAs:    proxyCertPool,
		ServerName: req.Host,
	}
	if a.clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*a.clientCert}
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}
	client := &http.Client{
		Transport: transport,
		// Do not follow redirect
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	res, err := client.Do(req)
	m.Must(err)
	m.SetLastResponse(res, err)

	return true
}

func (a *Agent) GetDashboard(m *btesting.Matcher) bool {
	dashboard := &proxyv1alpha2.Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name: "e2e-dashboard",
		},
	}
	return a.Get(m, dashboard, nil)
}

type EtcdClusters struct {
	restConfig *rest.Config
	coreClient *kubernetes.Clientset
	client     *client.Set

	clusters map[string]*etcdv1alpha2.EtcdCluster
}

func (e *EtcdClusters) Setup(m *btesting.Matcher, traits ...k8sfactory.Trait) bool {
	etcdCluster := etcd.Factory(EtcdClusterBase, traits...)
	_, err := e.client.EtcdV1alpha2.CreateEtcdCluster(context.Background(), etcdCluster, metav1.CreateOptions{})
	m.Must(err)
	e.clusters[etcdCluster.GetName()] = etcdCluster
	return m.Must(e2eutil.WaitForStatusOfEtcdClusterBecome(e.client, etcdCluster, etcdv1alpha2.EtcdClusterPhaseRunning, 10*time.Minute))
}

func (e *EtcdClusters) EtcdCluster(name string) *EtcdCluster {
	if v, ok := e.clusters[name]; ok {
		return &EtcdCluster{
			EtcdCluster: v,
			restConfig:  e.restConfig,
			coreClient:  e.coreClient,
			clusters:    e,
		}
	}
	return &EtcdCluster{}
}

func (e *EtcdClusters) Reload(name string) error {
	ec, ok := e.clusters[name]
	if !ok {
		return nil
	}
	newEC, err := e.client.EtcdV1alpha2.GetEtcdCluster(context.Background(), ec.Namespace, ec.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	e.clusters[name] = newEC
	return nil
}

type EtcdCluster struct {
	*etcdv1alpha2.EtcdCluster

	clusters   *EtcdClusters
	coreClient *kubernetes.Clientset
	restConfig *rest.Config
}

func (c *EtcdCluster) Reload() {
	if c.EtcdCluster == nil {
		return
	}
	c.clusters.Reload(c.EtcdCluster.Name)
	c.EtcdCluster = c.clusters.EtcdCluster(c.Name).EtcdCluster
}

func (c *EtcdCluster) Client(m *btesting.Matcher) *e2eutil.EtcdClient {
	if c.EtcdCluster == nil {
		return nil
	}
	ecClient, err := e2eutil.NewEtcdClient(c.coreClient, c.restConfig, c.EtcdCluster)
	if err != nil {
		m.Failf("Failed connect to etcd cluster: %v", err)
	}
	return ecClient
}

func (c *EtcdCluster) Destroy(client *client.Set) {
	if c.EtcdCluster == nil {
		return
	}
	_ = client.EtcdV1alpha2.DeleteEtcdCluster(context.TODO(), c.Namespace, c.Name, metav1.DeleteOptions{})
}

func (c *EtcdCluster) Update(m *btesting.Matcher, client *client.Set, traits ...k8sfactory.Trait) {
	c.Reload()
	newEC := etcd.Factory(c.EtcdCluster, traits...)
	_, err := client.EtcdV1alpha2.UpdateEtcdCluster(context.TODO(), newEC, metav1.UpdateOptions{})
	if err != nil {
		m.Failf("Failed to update etcd cluster: %v", err)
	}
	c.Reload()
}

func (c *EtcdCluster) WaitBecome(m *btesting.Matcher, client *client.Set, status etcdv1alpha2.EtcdClusterPhase) {
	m.Must(e2eutil.WaitForStatusOfEtcdClusterBecome(client, c.EtcdCluster, status, 10*time.Minute))
}

func (c *EtcdCluster) NumOfPods(m *btesting.Matcher, length int) {
	if c.EtcdCluster == nil {
		m.Fail("EtcdCluster is not found")
	}
	pods, err := c.coreClient.CoreV1().Pods(c.EtcdCluster.Namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", etcd.LabelNameClusterName, c.EtcdCluster.Name)})
	m.NoError(err)
	m.Len(pods.Items, length)
}

func (c *EtcdCluster) EqualVersion(m *btesting.Matcher, version string) {
	if c.EtcdCluster == nil {
		m.Fail("EtcdCluster is not found")
	}
	pods, err := c.coreClient.CoreV1().Pods(c.EtcdCluster.Namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", etcd.LabelNameClusterName, c.EtcdCluster.Name)})
	m.NoError(err)
	if len(pods.Items) == 0 {
		m.Fail("Pod is not found")
	}
	for _, pod := range pods.Items {
		m.Equal(version, pod.Labels[etcd.LabelNameEtcdVersion])
	}
}

func (c *EtcdCluster) HavePVC(m *btesting.Matcher) {
	c.haveDataVolume(m, "pvc")
}

func (c *EtcdCluster) HaveEmptyDir(m *btesting.Matcher) {
	c.haveDataVolume(m, "emptydir")
}

func (c *EtcdCluster) Ready(m *btesting.Matcher) {
	if c.EtcdCluster == nil {
		m.Fail("etcd cluster is not found")
	}
	m.True(c.EtcdCluster.Status.Ready)
}

func (c *EtcdCluster) haveDataVolume(m *btesting.Matcher, source string) {
	if c.EtcdCluster == nil {
		m.Fail("etcd cluster is not found")
	}
	pods, err := c.coreClient.CoreV1().Pods(c.EtcdCluster.Namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", etcd.LabelNameClusterName, c.EtcdCluster.Name)})
	m.Must(err)
	found := false
	for _, pod := range pods.Items {
		for _, vol := range pod.Spec.Volumes {
			if vol.Name == "data" {
				found = true
				switch source {
				case "pvc":
					m.NotNil(vol.PersistentVolumeClaim)
				case "emptydir":
					m.NotNil(vol.EmptyDir)
				}
			}
		}
	}
	if !found {
		m.Fail("could not found data volume")
	}
}
