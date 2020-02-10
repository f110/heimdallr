package controllers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	mrand "math/rand"
	"sort"
	"sync"

	"github.com/go-logr/logr"

	"github.com/f110/lagrangian-proxy/pkg/cert"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/k8s"
	"github.com/f110/lagrangian-proxy/pkg/netutil"

	etcdcluster "github.com/coreos/etcd-operator/pkg/apis/etcd/v1beta2"
	monitoringv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	proxyv1 "github.com/f110/lagrangian-proxy/operator/pkg/api/v1"
)

const (
	EtcdVersion = "3.3.18"

	imageRepository            = "quay.io/f110/lagrangian-proxy"
	defaultImageTag            = "latest"
	rpcServerImageRepositry    = "quay.io/f110/lagrangian-proxy-rpcserver"
	ctlImageRepository         = "quay.io/f110/lagrangian-proxy-ctl"
	defaultCommand             = "/usr/local/bin/lagrangian-proxy"
	rpcServerCommand           = "/usr/local/bin/lag-rpcserver"
	ctlCommand                 = "/usr/local/bin/lagctl"
	proxyPort                  = 4000
	proxyHttpPort              = 4002
	internalApiPort            = 4004
	dashboardPort              = 4100
	rpcServerPort              = 4001
	rpcMetricsServerPort       = 4005
	configVolumePath           = "/etc/lagrangian-proxy"
	configMountPath            = configVolumePath + "/config"
	proxyConfigMountPath       = configVolumePath + "/proxy"
	serverCertMountPath        = configVolumePath + "/certs"
	caCertMountPath            = configVolumePath + "/ca"
	identityProviderSecretPath = configVolumePath + "/idp"
	sessionSecretPath          = configVolumePath + "/session"
	signPrivateKeyPath         = configVolumePath + "/privkey"
	githubSecretPath           = configVolumePath + "/github_secret"
	internalTokenMountPath     = configVolumePath + "/internal_token"

	configFilename              = "config.yaml"
	privateKeyFilename          = "privkey.pem"
	githubWebhookSecretFilename = "webhook_secret"
	internalTokenFilename       = "internal_token"
	cookieSecretFilename        = "cookie_secret"
	serverCertificateFilename   = "tls.crt"
	serverPrivateKeyFilename    = "tls.key"
	caCertificateFilename       = "ca.crt"
	caPrivateKeyFilename        = "ca.key"
	proxyFilename               = "proxies.yaml"
	roleFilename                = "roles.yaml"
	rpcPermissionFilename       = "rpc_permissions.yaml"

	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

type process struct {
	Deployment          *appsv1.Deployment
	PodDisruptionBudget *policyv1beta1.PodDisruptionBudget
	Service             []*corev1.Service
	ConfigMaps          []*corev1.ConfigMap
	Secrets             []*corev1.Secret
	Certificate         *certmanager.Certificate
	CronJob             *batchv1beta1.CronJob
	ServiceMonitors     []*monitoringv1.ServiceMonitor
}

type LagrangianProxy struct {
	sync.Mutex

	Name      string
	Namespace string
	Object    *proxyv1.Proxy
	Spec      proxyv1.ProxySpec
	Client    client.Client
	Log       logr.Logger

	selfSignedIssuer bool
	caSecretName     string
	caFilename       string
}

func NewLagrangianProxy(spec *proxyv1.Proxy, client client.Client, log logr.Logger) *LagrangianProxy {
	return &LagrangianProxy{
		Name:      spec.Name,
		Namespace: spec.Namespace,
		Client:    client,
		Log:       log,
		Object:    spec,
		Spec:      spec.Spec,
	}
}

func (r *LagrangianProxy) Version() string {
	if r.Spec.Version != "" {
		return r.Spec.Version
	}

	return defaultImageTag
}

func (r *LagrangianProxy) EtcdClusterName() string {
	return r.Name + "-datastore"
}

func (r *LagrangianProxy) CertificateSecretName() string {
	return r.Name + "-cert"
}

func (r *LagrangianProxy) CASecretName() string {
	return r.Name + "-ca"
}

func (r *LagrangianProxy) PrivateKeySecretName() string {
	return r.Name + "-privkey"
}

func (r *LagrangianProxy) GithubSecretName() string {
	return r.Name + "-github-secret"
}

func (r *LagrangianProxy) InternalTokenSecretName() string {
	return r.Name + "-internal-token"
}

func (r *LagrangianProxy) CookieSecretName() string {
	switch r.Spec.Session.Type {
	case config.SessionTypeSecureCookie:
		return r.Name + "-cookie-secret"
	default:
		return r.Spec.Session.KeySecretRef.Name
	}
}

func (r *LagrangianProxy) EtcdHost() string {
	return r.EtcdClusterName() + "-client"
}

func (r *LagrangianProxy) ConfigNameForMain() string {
	return r.Name
}

func (r *LagrangianProxy) ConfigNameForDashboard() string {
	return r.Name + "-dashboard"
}

func (r *LagrangianProxy) ConfigNameForRPCServer() string {
	return r.Name + "-rpcserver"
}

func (r *LagrangianProxy) ConfigNameForDefragmentCronJob() string {
	return r.Name + "-defragment"
}

func (r *LagrangianProxy) DeploymentNameForMain() string {
	return r.Name
}

func (r *LagrangianProxy) PodDisruptionBudgetNameForMain() string {
	return r.Name
}

func (r *LagrangianProxy) ServiceNameForMain() string {
	return r.Name
}

func (r *LagrangianProxy) DeploymentNameForDashboard() string {
	return r.Name + "-dashboard"
}

func (r *LagrangianProxy) DeploymentNameForRPCServer() string {
	return r.Name + "-rpcserver"
}

func (r *LagrangianProxy) PodDisruptionBudgetNameForDashboard() string {
	return r.Name + "-dashboard"
}

func (r *LagrangianProxy) ServiceNameForDashboard() string {
	return r.Name + "-dashboard"
}

func (r *LagrangianProxy) ServiceNameForRPCServer() string {
	return r.Name + "-rpcserver"
}

func (r *LagrangianProxy) ReverseProxyConfigName() string {
	return r.Name + "-proxy"
}

func (r *LagrangianProxy) ServiceNameForInternalApi() string {
	return r.Name + "-internal"
}

func (r *LagrangianProxy) DefragmentCronJobName() string {
	return r.Name + "-defragment"
}

func (r *LagrangianProxy) Backends() ([]proxyv1.Backend, error) {
	selector, err := metav1.LabelSelectorAsSelector(&r.Spec.BackendSelector.LabelSelector)
	if err != nil {
		return nil, err
	}
	backends := &proxyv1.BackendList{}
	if err := r.Client.List(context.Background(), backends, &client.ListOptions{LabelSelector: selector, Namespace: r.Spec.BackendSelector.Namespace}); err != nil {
		return nil, err
	}

	res := backends.Items

	found := false
	for _, v := range backends.Items {
		if v.Name == "dashboard" && v.Namespace == r.Namespace && v.Spec.Layer == "" {
			found = true
			break
		}
	}

	if !found {
		res = append(res, proxyv1.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dashboard",
				Namespace: r.Namespace,
			},
			Spec: proxyv1.BackendSpec{
				Upstream:      fmt.Sprintf("http://%s:%d", r.ServiceNameForDashboard(), dashboardPort),
				AllowRootUser: true,
				Permissions: []proxyv1.Permission{
					{
						Name: "all",
						Locations: []proxyv1.Location{
							{Any: "/"},
						},
					},
				},
			},
		})
	}

	return res, nil
}

func (r *LagrangianProxy) Roles() ([]proxyv1.Role, error) {
	selector, err := metav1.LabelSelectorAsSelector(&r.Spec.RoleSelector.LabelSelector)
	if err != nil {
		return nil, err
	}
	roleList := &proxyv1.RoleList{}
	if err := r.Client.List(context.Background(), roleList, &client.ListOptions{LabelSelector: selector, Namespace: r.Spec.RoleSelector.Namespace}); err != nil {
		return nil, err
	}

	res := roleList.Items
	found := false
	for _, v := range roleList.Items {
		if v.Name == "admin" && v.Namespace == r.Namespace {
			found = true
			break
		}
	}
	if !found {
		res = append(res, proxyv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "admin",
				Namespace: r.Namespace,
			},
			Spec: proxyv1.RoleSpec{
				Title:       "administrator",
				Description: fmt.Sprintf("%s administrators", r.Name),
				Bindings: []proxyv1.Binding{
					{BackendName: "dashboard", Namespace: r.Namespace, Permission: "all"},
					{RpcPermissionName: "admin"},
				},
			},
		})
	}

	return res, nil
}

func (r *LagrangianProxy) RpcPermissions() ([]proxyv1.RpcPermission, error) {
	selector, err := metav1.LabelSelectorAsSelector(&r.Spec.RpcPermissionSelector.LabelSelector)
	if err != nil {
		return nil, err
	}
	rpcPermissionList := &proxyv1.RpcPermissionList{}
	if err := r.Client.List(context.Background(), rpcPermissionList, &client.ListOptions{LabelSelector: selector, Namespace: r.Spec.RpcPermissionSelector.Namespace}); err != nil {
		return nil, err
	}

	res := rpcPermissionList.Items
	found := false
	for _, v := range rpcPermissionList.Items {
		if v.Name == "admin" && v.Namespace == r.Namespace {
			found = true
			break
		}
	}
	if !found {
		res = append(res, proxyv1.RpcPermission{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "admin",
				Namespace: r.Namespace,
			},
			Spec: proxyv1.RpcPermissionSpec{
				Allow: []string{"proxy.rpc.admin.*", "proxy.rpc.certificateauthority.*"},
			},
		})
	}

	return res, nil
}

func (r *LagrangianProxy) Certificate() (*certmanager.Certificate, error) {
	backends, err := r.Backends()
	if err != nil {
		return nil, err
	}
	layers := make(map[string]struct{})
	fqdn := make([]string, 0)
	for _, v := range backends {
		if v.Spec.Layer == "" {
			if v.Spec.FQDN != "" {
				fqdn = append(fqdn, v.Spec.FQDN)
			}
			continue
		}

		if _, ok := layers[v.Spec.Layer]; !ok {
			layers[v.Spec.Layer] = struct{}{}
		}
	}

	domains := []string{r.Spec.Domain, fmt.Sprintf("*.%s", r.Spec.Domain)}
	domains = append(domains, fqdn...)
	for v := range layers {
		domains = append(domains, fmt.Sprintf("*.%s.%s", v, r.Spec.Domain))
	}
	sort.Strings(domains)

	cert := &certmanager.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: r.Name, Namespace: r.Namespace},
		Spec: certmanager.CertificateSpec{
			SecretName: r.CertificateSecretName(),
			IssuerRef:  r.Spec.IssuerRef,
			CommonName: r.Spec.Domain,
			DNSNames:   domains,
		},
	}

	return cert, nil
}

func (r *LagrangianProxy) EtcdCluster() (*etcdcluster.EtcdCluster, *monitoringv1.ServiceMonitor) {
	cluster := &etcdcluster.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{Name: r.EtcdClusterName(), Namespace: r.Namespace},
		Spec: etcdcluster.ClusterSpec{
			Size:    3,
			Version: EtcdVersion,
		},
	}
	var sm *monitoringv1.ServiceMonitor
	if r.Spec.Monitor.PrometheusMonitoring {
		sm = &monitoringv1.ServiceMonitor{
			ObjectMeta: metav1.ObjectMeta{
				Name:      r.EtcdClusterName(),
				Namespace: r.Namespace,
				Labels:    r.Spec.Monitor.Labels,
			},
			Spec: monitoringv1.ServiceMonitorSpec{
				JobLabel: "proxy.f110.dev/name",
				Selector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"app":          "etcd",
						"etcd_cluster": r.EtcdClusterName(),
					},
				},
				NamespaceSelector: monitoringv1.NamespaceSelector{
					MatchNames: []string{r.Namespace},
				},
				Endpoints: []monitoringv1.Endpoint{
					{Port: "client", Interval: "30s", HonorLabels: true},
				},
			},
		}
	}

	return cluster, sm
}

func (r *LagrangianProxy) CASecret() (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.CASecretName(),
			Namespace: r.Namespace,
		},
		Data: make(map[string][]byte),
	}
	key, err := client.ObjectKeyFromObject(secret)
	if err != nil {
		return nil, err
	}

	err = r.Client.Get(context.Background(), key, secret)
	if apierrors.IsNotFound(err) {
		caName := "Lagrangian Proxy CA"
		if r.Spec.Name != "" {
			caName = r.Spec.Name
		}
		country := "jp"
		if r.Spec.Country != "" {
			country = r.Spec.Country
		}
		cert, privateKey, err := cert.CreateCertificateAuthority(caName, r.Spec.Organization, r.Spec.AdministratorUnit, country)
		if err != nil {
			return nil, err
		}

		b, err := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, err
		}

		buf := new(bytes.Buffer)
		if err := pem.Encode(buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
			return nil, err
		}
		secret.Data[caPrivateKeyFilename] = buf.Bytes()

		buf = new(bytes.Buffer)
		if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			return nil, err
		}
		secret.Data[caCertificateFilename] = buf.Bytes()
	}

	return secret, nil
}

func (r *LagrangianProxy) PrivateKeyForSign() (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.PrivateKeySecretName(),
			Namespace: r.Namespace,
		},
		Data: make(map[string][]byte),
	}
	key, err := client.ObjectKeyFromObject(secret)
	if err != nil {
		return nil, err
	}

	err = r.Client.Get(context.Background(), key, secret)
	if apierrors.IsNotFound(err) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		b, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
		buf := new(bytes.Buffer)
		if err := pem.Encode(buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
			return nil, err
		}
		secret.Data[privateKeyFilename] = buf.Bytes()
	}

	return secret, nil
}

func (r *LagrangianProxy) GithubSecret() (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.GithubSecretName(),
			Namespace: r.Namespace,
		},
		Data: make(map[string][]byte),
	}
	key, err := client.ObjectKeyFromObject(secret)
	if err != nil {
		return nil, err
	}

	err = r.Client.Get(context.Background(), key, secret)
	if apierrors.IsNotFound(err) {
		b := make([]byte, 32)
		for i := range b {
			b[i] = letters[mrand.Intn(len(letters))]
		}
		secret.Data[githubWebhookSecretFilename] = b
	}

	return secret, nil
}

func (r *LagrangianProxy) CookieSecret() (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.CookieSecretName(),
			Namespace: r.Namespace,
		},
		Data: make(map[string][]byte),
	}
	key, err := client.ObjectKeyFromObject(secret)
	if err != nil {
		return nil, err
	}

	err = r.Client.Get(context.Background(), key, secret)
	if apierrors.IsNotFound(err) {
		hashKey := make([]byte, 32)
		for i := range hashKey {
			hashKey[i] = letters[mrand.Intn(len(letters))]
		}
		blockKey := make([]byte, 16)
		for i := range blockKey {
			blockKey[i] = letters[mrand.Intn(len(letters))]
		}
		buf := new(bytes.Buffer)
		buf.Write(hashKey)
		buf.WriteRune('\n')
		buf.Write(blockKey)
		secret.Data[cookieSecretFilename] = buf.Bytes()
	}

	return secret, nil
}

func (r *LagrangianProxy) InternalTokenSecret() (*corev1.Secret, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.InternalTokenSecretName(),
			Namespace: r.Namespace,
		},
		Data: make(map[string][]byte),
	}
	key, err := client.ObjectKeyFromObject(secret)
	if err != nil {
		return nil, err
	}

	err = r.Client.Get(context.Background(), key, secret)
	if apierrors.IsNotFound(err) {
		b := make([]byte, 32)
		for i := range b {
			b[i] = letters[mrand.Intn(len(letters))]
		}
		secret.Data[internalTokenFilename] = b
	}

	return secret, nil
}

func (r *LagrangianProxy) ConfigForMain() (*corev1.ConfigMap, error) {
	conf := &config.Config{
		General: &config.General{
			Enable:            true,
			Bind:              fmt.Sprintf(":%d", proxyPort),
			ServerName:        r.Spec.Domain,
			RpcTarget:         fmt.Sprintf("%s:%d", r.ServiceNameForRPCServer(), rpcServerPort),
			RootUsers:         r.Spec.RootUsers,
			CertFile:          fmt.Sprintf("%s/%s", serverCertMountPath, serverCertificateFilename),
			KeyFile:           fmt.Sprintf("%s/%s", serverCertMountPath, serverPrivateKeyFilename),
			RoleFile:          fmt.Sprintf("%s/%s", proxyConfigMountPath, roleFilename),
			ProxyFile:         fmt.Sprintf("%s/%s", proxyConfigMountPath, proxyFilename),
			RpcPermissionFile: fmt.Sprintf("%s/%s", proxyConfigMountPath, rpcPermissionFilename),
			CertificateAuthority: &config.CertificateAuthority{
				CertFile: fmt.Sprintf("%s/%s", caCertMountPath, caCertificateFilename),
			},
			InternalTokenFile: fmt.Sprintf("%s/%s", internalTokenMountPath, internalTokenFilename),
		},
		IdentityProvider: &config.IdentityProvider{
			Provider:         r.Spec.IdentityProvider.Provider,
			ClientId:         r.Spec.IdentityProvider.ClientId,
			ClientSecretFile: fmt.Sprintf("%s/%s", identityProviderSecretPath, r.Spec.IdentityProvider.ClientSecretRef.Key),
			ExtraScopes:      []string{"email"},
			RedirectUrl:      r.Spec.IdentityProvider.RedirectUrl,
		},
		Datastore: &config.Datastore{
			RawUrl:    fmt.Sprintf("etcd://%s:2379", r.EtcdHost()),
			Namespace: "/lagrangian-proxy/",
		},
		FrontendProxy: &config.FrontendProxy{
			GithubWebHookSecretFile: fmt.Sprintf("%s/%s", githubSecretPath, githubWebhookSecretFilename),
			ExpectCT:                true,
			Session: &config.Session{
				Type:    r.Spec.Session.Type,
				KeyFile: fmt.Sprintf("%s/%s", sessionSecretPath, cookieSecretFilename),
			},
		},
		Logger: &config.Logger{
			Level:    "info",
			Encoding: "console",
		},
		Dashboard: &config.Dashboard{
			Enable: false,
		},
	}
	if r.Spec.HttpPort != 0 {
		conf.General.EnableHttp = true
		conf.General.BindHttp = fmt.Sprintf(":%d", proxyHttpPort)
	}
	b, err := yaml.Marshal(conf)
	if err != nil {
		return nil, err
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.ConfigNameForMain(),
			Namespace: r.Namespace,
		},
		Data: make(map[string]string),
	}
	configMap.Data[configFilename] = string(b)

	return configMap, nil
}

func (r *LagrangianProxy) ConfigForDashboard() (*corev1.ConfigMap, error) {
	conf := &config.Config{
		General: &config.General{
			Enable:     false,
			ServerName: r.Spec.Domain,
			RpcTarget:  fmt.Sprintf("%s:%d", r.ServiceNameForRPCServer(), rpcServerPort),
			CertificateAuthority: &config.CertificateAuthority{
				CertFile: fmt.Sprintf("%s/%s", caCertMountPath, caCertificateFilename),
			},
			InternalTokenFile: fmt.Sprintf("%s/%s", internalTokenMountPath, internalTokenFilename),
		},
		Logger: &config.Logger{
			Level:    "info",
			Encoding: "console",
		},
		Dashboard: &config.Dashboard{
			Enable: true,
			Bind:   fmt.Sprintf(":%d", dashboardPort),
		},
	}
	b, err := yaml.Marshal(conf)
	if err != nil {
		return nil, err
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.ConfigNameForDashboard(),
			Namespace: r.Namespace,
		},
		Data: make(map[string]string),
	}
	configMap.Data[configFilename] = string(b)

	return configMap, nil
}

func (r *LagrangianProxy) ConfigForRPCServer() (*corev1.ConfigMap, error) {
	conf := &config.Config{
		General: &config.General{
			Enable:            true,
			ServerName:        r.Spec.Domain,
			RoleFile:          fmt.Sprintf("%s/%s", proxyConfigMountPath, roleFilename),
			ProxyFile:         fmt.Sprintf("%s/%s", proxyConfigMountPath, proxyFilename),
			RpcPermissionFile: fmt.Sprintf("%s/%s", proxyConfigMountPath, rpcPermissionFilename),
			CertificateAuthority: &config.CertificateAuthority{
				CertFile:         fmt.Sprintf("%s/%s", caCertMountPath, caCertificateFilename),
				KeyFile:          fmt.Sprintf("%s/%s", caCertMountPath, caPrivateKeyFilename),
				Organization:     r.Spec.Organization,
				OrganizationUnit: r.Spec.AdministratorUnit,
				Country:          r.Spec.Country,
			},
			RootUsers:             r.Spec.RootUsers,
			SigningPrivateKeyFile: fmt.Sprintf("%s/%s", signPrivateKeyPath, privateKeyFilename),
			InternalTokenFile:     fmt.Sprintf("%s/%s", internalTokenMountPath, internalTokenFilename),
		},
		Logger: &config.Logger{
			Level:    "info",
			Encoding: "console",
		},
		Datastore: &config.Datastore{
			RawUrl:    fmt.Sprintf("etcd://%s:2379", r.EtcdHost()),
			Namespace: "/lagrangian-proxy/",
		},
		RPCServer: &config.RPCServer{
			Bind:   fmt.Sprintf(":%d", rpcServerPort),
			Enable: true,
		},
		Dashboard: &config.Dashboard{
			Enable: false,
		},
	}
	if r.Spec.Monitor.PrometheusMonitoring {
		conf.RPCServer.MetricsBind = fmt.Sprintf(":%d", rpcMetricsServerPort)
	}

	b, err := yaml.Marshal(conf)
	if err != nil {
		return nil, err
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.ConfigNameForRPCServer(),
			Namespace: r.Namespace,
		},
		Data: make(map[string]string),
	}
	configMap.Data[configFilename] = string(b)

	return configMap, nil
}

func (r *LagrangianProxy) ConfigForDefragmentCronJob() (*corev1.ConfigMap, error) {
	conf := &config.Config{
		General: &config.General{
			Enable:     false,
			ServerName: r.Spec.Domain,
			RpcTarget:  fmt.Sprintf("%s:%d", r.ServiceNameForRPCServer(), rpcServerPort),
			CertificateAuthority: &config.CertificateAuthority{
				CertFile: fmt.Sprintf("%s/%s", caCertMountPath, caCertificateFilename),
			},
			SigningPrivateKeyFile: fmt.Sprintf("%s/%s", signPrivateKeyPath, privateKeyFilename),
			InternalTokenFile:     fmt.Sprintf("%s/%s", internalTokenMountPath, internalTokenFilename),
		},
		Logger: &config.Logger{
			Level:    "info",
			Encoding: "console",
		},
		Datastore: &config.Datastore{
			RawUrl:    fmt.Sprintf("etcd://%s:2379", r.EtcdHost()),
			Namespace: "/lagrangian-proxy/",
		},
		RPCServer: &config.RPCServer{
			Enable: false,
		},
		Dashboard: &config.Dashboard{
			Enable: false,
		},
	}
	b, err := yaml.Marshal(conf)
	if err != nil {
		return nil, err
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.ConfigNameForDefragmentCronJob(),
			Namespace: r.Namespace,
		},
		Data: make(map[string]string),
	}
	configMap.Data[configFilename] = string(b)

	return configMap, nil
}

func (r *LagrangianProxy) LabelsForMain() map[string]string {
	return map[string]string{"app": "lagrangian-proxy", "instance": r.Name, "role": "proxy"}
}

func (r *LagrangianProxy) LabelsForDashboard() map[string]string {
	return map[string]string{"app": "lagrangian-proxy", "instance": r.Name, "role": "dashboard"}
}

func (r *LagrangianProxy) LabelsForRPCServer() map[string]string {
	return map[string]string{"app": "lagrangian-proxy", "instance": r.Name, "role": "rpcserver"}
}

func (r *LagrangianProxy) LabelsForDefragmentJob() map[string]string {
	return map[string]string{"app": "lagrangian-proxy", "instance": r.Name, "role": "job", "job": "defragment"}
}

func (r *LagrangianProxy) ReverseProxyConfig() (*corev1.ConfigMap, error) {
	backends, err := r.Backends()
	if err != nil {
		return nil, err
	}

	clusterDomain, err := k8s.GetClusterDomain()
	if err != nil {
		clusterDomain = "cluster.local"
	}
	proxies := make([]*config.Backend, len(backends))
	backendMap := make(map[string]proxyv1.Backend)
	for i, v := range backends {
		backendMap[v.Namespace+"/"+v.Name] = v

		var service *corev1.Service
		if len(v.Spec.ServiceSelector.MatchLabels) > 0 {
			selector, err := metav1.LabelSelectorAsSelector(&v.Spec.ServiceSelector.LabelSelector)
			if err != nil {
				return nil, err
			}

			svc := &corev1.ServiceList{}
			if err := r.Client.List(context.Background(), svc, &client.ListOptions{LabelSelector: selector, Namespace: r.Spec.BackendSelector.Namespace}); err != nil {
				return nil, err
			}
			if len(svc.Items) == 0 {
				continue
			}

			service = &svc.Items[0]
		}

		permissions := make([]*config.Permission, len(v.Spec.Permissions))
		for k, p := range v.Spec.Permissions {
			locations := make([]config.Location, len(p.Locations))
			for j, u := range p.Locations {
				locations[j] = config.Location{
					Any:     u.Any,
					Get:     u.Get,
					Post:    u.Post,
					Put:     u.Put,
					Delete:  u.Delete,
					Head:    u.Head,
					Connect: u.Connect,
					Options: u.Options,
					Trace:   u.Trace,
					Patch:   u.Patch,
				}
			}
			permissions[k] = &config.Permission{
				Name:      v.Spec.Permissions[k].Name,
				Locations: locations,
			}
		}
		name := v.Name + "." + v.Spec.Layer
		if v.Spec.Layer == "" {
			name = v.Name
		}
		upstream := v.Spec.Upstream
		if upstream == "" && service != nil {
			for _, p := range service.Spec.Ports {
				if p.Name == v.Spec.ServiceSelector.Port {
					scheme := v.Spec.ServiceSelector.Scheme
					if scheme == "" {
						switch p.Name {
						case "http", "https":
							scheme = p.Name
						}
					}

					upstream = fmt.Sprintf("%s://%s.%s.svc.%s:%d", scheme, service.Name, service.Namespace, clusterDomain, p.Port)
					break
				}
			}
		}
		proxies[i] = &config.Backend{
			Name:            name,
			FQDN:            v.Spec.FQDN,
			Upstream:        upstream,
			Permissions:     permissions,
			WebHook:         v.Spec.Webhook,
			WebHookPath:     v.Spec.WebhookPath,
			Agent:           v.Spec.Agent,
			AllowAsRootUser: v.Spec.AllowRootUser,
			DisableAuthn:    v.Spec.DisableAuthn,
			Insecure:        v.Spec.Insecure,
			AllowHttp:       v.Spec.AllowHttp,
		}
	}
	proxyBinary, err := yaml.Marshal(proxies)
	if err != nil {
		return nil, err
	}

	roleList, err := r.Roles()
	if err != nil {
		return nil, err
	}
	roles := make([]*config.Role, len(roleList))
	for i, v := range roleList {
		bindings := make([]*config.Binding, len(v.Spec.Bindings))
		for k, b := range v.Spec.Bindings {
			switch {
			case b.BackendName != "":
				namespace := v.Namespace
				if b.Namespace != "" {
					namespace = b.Namespace
				}
				backendHost := ""
				if bn, ok := backendMap[namespace+"/"+b.BackendName]; ok {
					backendHost = bn.Name + "." + bn.Spec.Layer
					if bn.Spec.Layer == "" {
						backendHost = bn.Name
					}
				} else {
					r.Log.Info(fmt.Sprintf("Ignore Backend/%s in Role/%s because backend not found", b.BackendName, v.Name))
					continue
				}

				bindings[k] = &config.Binding{
					Permission: b.Permission,
					Backend:    backendHost,
				}
			case b.RpcPermissionName != "":
				bindings[k] = &config.Binding{
					Rpc: b.RpcPermissionName,
				}
			}
		}

		roles[i] = &config.Role{
			Name:        v.Name,
			Title:       v.Spec.Title,
			Description: v.Spec.Description,
			Bindings:    bindings,
		}
	}
	roleBinary, err := yaml.Marshal(roles)
	if err != nil {
		return nil, err
	}

	rpcPermissionList, err := r.RpcPermissions()
	if err != nil {
		return nil, err
	}
	rpcPermissions := make([]*config.RpcPermission, len(rpcPermissionList))
	for i, v := range rpcPermissionList {
		rpcPermissions[i] = &config.RpcPermission{
			Name:  v.Name,
			Allow: v.Spec.Allow,
		}
	}
	rpcPermissionBinary, err := yaml.Marshal(rpcPermissions)
	if err != nil {
		return nil, err
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.ReverseProxyConfigName(),
			Namespace: r.Namespace,
		},
		Data: make(map[string]string),
	}
	configMap.Data[roleFilename] = string(roleBinary)
	configMap.Data[proxyFilename] = string(proxyBinary)
	configMap.Data[rpcPermissionFilename] = string(rpcPermissionBinary)

	return configMap, nil
}

func (r *LagrangianProxy) Main() (*process, error) {
	secret := &corev1.Secret{}
	err := r.Client.Get(context.Background(), client.ObjectKey{Name: r.Spec.IdentityProvider.ClientSecretRef.Name, Namespace: r.Namespace}, secret)
	if err != nil && apierrors.IsNotFound(err) {
		return nil, err
	}

	var cronJob *batchv1beta1.CronJob
	var defragmentConf *corev1.ConfigMap
	if r.Spec.Defragment.Schedule != "" {
		cronJob = &batchv1beta1.CronJob{
			ObjectMeta: metav1.ObjectMeta{
				Name:      r.DefragmentCronJobName(),
				Namespace: r.Namespace,
			},
			Spec: batchv1beta1.CronJobSpec{
				Schedule: r.Spec.Defragment.Schedule,
				JobTemplate: batchv1beta1.JobTemplateSpec{
					Spec: batchv1.JobSpec{
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{
								Labels: r.LabelsForDefragmentJob(),
							},
							Spec: corev1.PodSpec{
								RestartPolicy: corev1.RestartPolicyNever,
								Containers: []corev1.Container{
									{
										Name:    "ctl",
										Image:   fmt.Sprintf("%s:%s", ctlImageRepository, r.Version()),
										Command: []string{ctlCommand},
										Args: []string{
											"internal",
											"defragment",
											"-c", fmt.Sprintf("%s/%s", configMountPath, configFilename),
										},
										Resources: corev1.ResourceRequirements{
											Requests: corev1.ResourceList{
												corev1.ResourceCPU:    resource.MustParse("100m"),
												corev1.ResourceMemory: resource.MustParse("128Mi"),
											},
											Limits: corev1.ResourceList{
												corev1.ResourceCPU:    resource.MustParse("1"),
												corev1.ResourceMemory: resource.MustParse("256Mi"),
											},
										},
										VolumeMounts: []corev1.VolumeMount{
											{Name: "privatekey", MountPath: signPrivateKeyPath, ReadOnly: true},
											{Name: "config", MountPath: configMountPath, ReadOnly: true},
											{Name: "ca-cert", MountPath: caCertMountPath, ReadOnly: true},
											{Name: "internal-token", MountPath: internalTokenMountPath, ReadOnly: true},
										},
									},
								},
								Volumes: []corev1.Volume{
									{
										Name: "ca-cert",
										VolumeSource: corev1.VolumeSource{
											Secret: &corev1.SecretVolumeSource{
												SecretName: r.CASecretName(),
												Items: []corev1.KeyToPath{
													{Key: caCertificateFilename, Path: caCertificateFilename},
												},
											},
										},
									},
									{
										Name: "privatekey",
										VolumeSource: corev1.VolumeSource{
											Secret: &corev1.SecretVolumeSource{
												SecretName: r.PrivateKeySecretName(),
											},
										},
									},
									{
										Name: "config",
										VolumeSource: corev1.VolumeSource{
											ConfigMap: &corev1.ConfigMapVolumeSource{
												LocalObjectReference: corev1.LocalObjectReference{
													Name: r.ConfigNameForDefragmentCronJob(),
												},
											},
										},
									},
									{
										Name: "internal-token",
										VolumeSource: corev1.VolumeSource{
											Secret: &corev1.SecretVolumeSource{
												SecretName: r.InternalTokenSecretName(),
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}

		defragmentConf, err = r.ConfigForDefragmentCronJob()
		if err != nil {
			return nil, err
		}
	}

	conf, err := r.ConfigForMain()
	if err != nil {
		return nil, err
	}
	confHash := sha256.Sum256([]byte(conf.Data[configFilename]))

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.DeploymentNameForMain(),
			Namespace: r.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &r.Spec.Replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: r.LabelsForMain(),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: r.LabelsForMain(),
					Annotations: map[string]string{
						fmt.Sprintf("checksum/%s", configFilename): hex.EncodeToString(confHash[:]),
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    "proxy",
							Image:   fmt.Sprintf("%s:%s", imageRepository, r.Version()),
							Command: []string{defaultCommand},
							Args:    []string{"-c", fmt.Sprintf("%s/%s", configMountPath, configFilename)},
							ReadinessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Scheme: corev1.URISchemeHTTP,
										Path:   "/readiness",
										Port:   intstr.FromInt(internalApiPort),
									},
								},
							},
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Scheme: corev1.URISchemeHTTP,
										Path:   "/liveness",
										Port:   intstr.FromInt(internalApiPort),
									},
								},
							},
							Env: []corev1.EnvVar{
								{
									Name: netutil.IPAddressEnvKey,
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "status.podIP",
										},
									},
								},
								{
									Name: netutil.NamespaceEnvKey,
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "metadata.namespace",
										},
									},
								},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("200m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("1"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "server-cert", MountPath: serverCertMountPath, ReadOnly: true},
								{Name: "ca-cert", MountPath: caCertMountPath, ReadOnly: true},
								{Name: "github-secret", MountPath: githubSecretPath, ReadOnly: true},
								{Name: "cookie-secret", MountPath: sessionSecretPath, ReadOnly: true},
								{Name: "config", MountPath: configMountPath, ReadOnly: true},
								{Name: "config-proxy", MountPath: proxyConfigMountPath, ReadOnly: true},
								{Name: "idp-secret", MountPath: identityProviderSecretPath, ReadOnly: true},
								{Name: "internal-token", MountPath: internalTokenMountPath, ReadOnly: true},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "server-cert",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: r.CertificateSecretName(),
								},
							},
						},
						{
							Name: "ca-cert",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: r.CASecretName(),
									Items: []corev1.KeyToPath{
										{Key: caCertificateFilename, Path: caCertificateFilename},
									},
								},
							},
						},
						{
							Name: "github-secret",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: r.GithubSecretName(),
								},
							},
						},
						{
							Name: "cookie-secret",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: r.CookieSecretName(),
								},
							},
						},
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: r.ConfigNameForMain(),
									},
								},
							},
						},
						{
							Name: "config-proxy",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: r.ReverseProxyConfigName(),
									},
								},
							},
						},
						{
							Name: "idp-secret",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: r.Spec.IdentityProvider.ClientSecretRef.Name,
								},
							},
						},
						{
							Name: "internal-token",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: r.InternalTokenSecretName(),
								},
							},
						},
					},
				},
			},
		},
	}

	minAvailable := intstr.FromInt(int(r.Spec.Replicas / 2))
	pdb := &policyv1beta1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.PodDisruptionBudgetNameForMain(),
			Namespace: r.Namespace,
		},
		Spec: policyv1beta1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: r.LabelsForMain(),
			},
			MinAvailable: &minAvailable,
		},
	}

	var port int32 = 443
	if r.Spec.Port != 0 {
		port = r.Spec.Port
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.ServiceNameForMain(),
			Namespace: r.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeLoadBalancer,
			Selector: r.LabelsForMain(),
			Ports: []corev1.ServicePort{
				{
					Name:       "https",
					Port:       port,
					TargetPort: intstr.FromInt(proxyPort),
				},
			},
			ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyTypeLocal,
		},
	}
	if r.Spec.HttpPort != 0 {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{
			Name:       "http",
			Port:       r.Spec.HttpPort,
			TargetPort: intstr.FromInt(proxyHttpPort),
		})
	}

	internalApiSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.ServiceNameForInternalApi(),
			Namespace: r.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: r.LabelsForMain(),
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       internalApiPort,
					TargetPort: intstr.FromInt(internalApiPort),
				},
			},
		},
	}

	reverseProxyConf, err := r.ReverseProxyConfig()
	if err != nil {
		return nil, err
	}

	caSecert, err := r.CASecret()
	if err != nil {
		return nil, err
	}
	githubSecret, err := r.GithubSecret()
	if err != nil {
		return nil, err
	}
	cookieSecret, err := r.CookieSecret()
	if err != nil {
		return nil, err
	}
	internalTokenSecret, err := r.InternalTokenSecret()
	if err != nil {
		return nil, err
	}

	cert, err := r.Certificate()
	if err != nil {
		return nil, err
	}

	return &process{
		Deployment:          deployment,
		PodDisruptionBudget: pdb,
		Service:             []*corev1.Service{svc, internalApiSvc},
		ConfigMaps:          []*corev1.ConfigMap{conf, reverseProxyConf, defragmentConf},
		Secrets: []*corev1.Secret{
			caSecert, githubSecret,
			cookieSecret, internalTokenSecret,
		},
		CronJob:     cronJob,
		Certificate: cert,
	}, nil
}

func (r *LagrangianProxy) Dashboard() (*process, error) {
	if err := r.checkSelfSignedIssuer(); err != nil {
		return nil, err
	}

	volumes := []corev1.Volume{
		{
			Name: "config",
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: r.ConfigNameForDashboard(),
					},
				},
			},
		},
		{
			Name: "internal-token",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: r.InternalTokenSecretName(),
				},
			},
		},
		{
			Name: "ca-cert",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: r.CASecretName(),
					Items: []corev1.KeyToPath{
						{Key: caCertificateFilename, Path: caCertificateFilename},
					},
				},
			},
		},
	}
	volumeMounts := []corev1.VolumeMount{
		{Name: "config", MountPath: configMountPath},
		{Name: "internal-token", MountPath: internalTokenMountPath, ReadOnly: true},
		{Name: "ca-cert", MountPath: caCertMountPath, ReadOnly: true},
	}

	if r.selfSignedIssuer {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      r.CertificateSecretName(),
				Namespace: r.Namespace,
			},
		}
		key, err := client.ObjectKeyFromObject(secret)
		if err != nil {
			return nil, err
		}
		err = r.Client.Get(context.Background(), key, secret)
		if apierrors.IsNotFound(err) {
			return nil, err
		}

		volumes = append(volumes, corev1.Volume{
			Name: "privatekey",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: r.PrivateKeySecretName(),
				},
			},
		})
		volumeMounts = append(volumeMounts,
			corev1.VolumeMount{Name: "privatekey", MountPath: signPrivateKeyPath, ReadOnly: true},
		)
	}

	conf, err := r.ConfigForDashboard()
	if err != nil {
		return nil, err
	}
	confHash := sha256.Sum256([]byte(conf.Data[configFilename]))

	var replicas int32 = 3
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.DeploymentNameForDashboard(),
			Namespace: r.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: r.LabelsForDashboard(),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: r.LabelsForDashboard(),
					Annotations: map[string]string{
						fmt.Sprintf("checksum/%s", configFilename): hex.EncodeToString(confHash[:]),
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    "proxy",
							Image:   fmt.Sprintf("%s:%s", imageRepository, r.Version()),
							Command: []string{defaultCommand},
							Args:    []string{"-c", fmt.Sprintf("%s/%s", configMountPath, configFilename)},
							ReadinessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/readiness",
										Port: intstr.FromInt(dashboardPort),
									},
								},
							},
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/liveness",
										Port: intstr.FromInt(dashboardPort),
									},
								},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("1"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
							},
							VolumeMounts: volumeMounts,
						},
					},
					Volumes: volumes,
				},
			},
		},
	}

	minAvailable := intstr.FromInt(int(replicas / 2))
	pdb := &policyv1beta1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.PodDisruptionBudgetNameForDashboard(),
			Namespace: r.Namespace,
		},
		Spec: policyv1beta1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: r.LabelsForDashboard(),
			},
			MinAvailable: &minAvailable,
		},
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.ServiceNameForDashboard(),
			Namespace: r.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: r.LabelsForDashboard(),
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       dashboardPort,
					TargetPort: intstr.FromInt(dashboardPort),
				},
			},
		},
	}

	caSecret, err := r.CASecret()
	if err != nil {
		return nil, err
	}
	internalTokenSecret, err := r.InternalTokenSecret()
	if err != nil {
		return nil, err
	}

	return &process{
		Deployment:          deployment,
		PodDisruptionBudget: pdb,
		Service:             []*corev1.Service{svc},
		Secrets:             []*corev1.Secret{caSecret, internalTokenSecret},
		ConfigMaps:          []*corev1.ConfigMap{conf},
	}, nil
}

func (r *LagrangianProxy) RPCServer() (*process, error) {
	caSecret, err := r.CASecret()
	if err != nil {
		return nil, err
	}

	conf, err := r.ConfigForRPCServer()
	if err != nil {
		return nil, err
	}
	confHash := sha256.Sum256([]byte(conf.Data[configFilename]))

	var replicas int32 = 2
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.DeploymentNameForRPCServer(),
			Namespace: r.Namespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: r.LabelsForRPCServer(),
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: r.LabelsForRPCServer(),
					Annotations: map[string]string{
						fmt.Sprintf("checksum/%s", configFilename): hex.EncodeToString(confHash[:]),
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    "rpcserver",
							Image:   fmt.Sprintf("%s:%s", rpcServerImageRepositry, r.Version()),
							Command: []string{rpcServerCommand},
							Args:    []string{"-c", fmt.Sprintf("%s/%s", configMountPath, configFilename)},
							ReadinessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									Exec: &corev1.ExecAction{
										Command: []string{
											"/usr/local/bin/grpc_health_probe",
											fmt.Sprintf("-addr=:%d", rpcServerPort),
											"-tls",
											fmt.Sprintf("-tls-ca-cert=%s/%s", caCertMountPath, caCertificateFilename),
											fmt.Sprintf("-tls-server-name=%s", r.Spec.Domain),
										},
									},
								},
								InitialDelaySeconds: 5,
							},
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									Exec: &corev1.ExecAction{
										Command: []string{
											"/usr/local/bin/grpc_health_probe",
											fmt.Sprintf("-addr=:%d", rpcServerPort),
											"-tls",
											fmt.Sprintf("-tls-ca-cert=%s/%s", caCertMountPath, caCertificateFilename),
											fmt.Sprintf("-tls-server-name=%s", r.Spec.Domain),
										},
									},
								},
								InitialDelaySeconds: 10,
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("1"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "ca-cert", MountPath: caCertMountPath, ReadOnly: true},
								{Name: "privatekey", MountPath: signPrivateKeyPath, ReadOnly: true},
								{Name: "config", MountPath: configMountPath, ReadOnly: true},
								{Name: "config-proxy", MountPath: proxyConfigMountPath, ReadOnly: true},
								{Name: "internal-token", MountPath: internalTokenMountPath, ReadOnly: true},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "ca-cert",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: r.CASecretName(),
								},
							},
						},
						{
							Name: "privatekey",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: r.PrivateKeySecretName(),
								},
							},
						},
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: r.ConfigNameForRPCServer(),
									},
								},
							},
						},
						{
							Name: "config-proxy",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: r.ReverseProxyConfigName(),
									},
								},
							},
						},
						{
							Name: "internal-token",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: r.InternalTokenSecretName(),
								},
							},
						},
					},
				},
			},
		},
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.ServiceNameForRPCServer(),
			Namespace: r.Namespace,
			Labels:    r.LabelsForRPCServer(),
		},
		Spec: corev1.ServiceSpec{
			Selector: r.LabelsForRPCServer(),
			Type:     corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       "h2",
					Port:       rpcServerPort,
					TargetPort: intstr.FromInt(rpcServerPort),
				},
			},
		},
	}
	internalTokenSecret, err := r.InternalTokenSecret()
	if err != nil {
		return nil, err
	}
	privateKey, err := r.PrivateKeyForSign()
	if err != nil {
		return nil, err
	}

	var rpcMetrics *monitoringv1.ServiceMonitor
	if r.Spec.Monitor.PrometheusMonitoring {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{
			Name: "metrics",
			Port: int32(rpcMetricsServerPort),
		})

		rpcMetrics = &monitoringv1.ServiceMonitor{
			ObjectMeta: metav1.ObjectMeta{
				Name:      r.ServiceNameForRPCServer(),
				Namespace: r.Namespace,
				Labels:    r.Spec.Monitor.Labels,
			},
			Spec: monitoringv1.ServiceMonitorSpec{
				JobLabel: "role",
				Selector: metav1.LabelSelector{
					MatchLabels: r.LabelsForRPCServer(),
				},
				NamespaceSelector: monitoringv1.NamespaceSelector{MatchNames: []string{r.Namespace}},
				Endpoints: []monitoringv1.Endpoint{
					{
						Port:        "metrics",
						Interval:    "30s",
						HonorLabels: true,
					},
				},
			},
		}
	}

	return &process{
		Deployment:      deployment,
		Service:         []*corev1.Service{svc},
		Secrets:         []*corev1.Secret{caSecret, privateKey, internalTokenSecret},
		ConfigMaps:      []*corev1.ConfigMap{conf},
		ServiceMonitors: []*monitoringv1.ServiceMonitor{rpcMetrics},
	}, nil
}

func (r *LagrangianProxy) checkSelfSignedIssuer() error {
	var issuerObj runtime.Object
	switch r.Spec.IssuerRef.Kind {
	case certmanager.ClusterIssuerKind:
		issuerObj = &certmanager.ClusterIssuer{
			ObjectMeta: metav1.ObjectMeta{
				Name: r.Spec.IssuerRef.Name,
			},
		}
	case certmanager.IssuerKind:
		issuerObj = &certmanager.Issuer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      r.Spec.IssuerRef.Name,
				Namespace: r.Namespace,
			},
		}
	}
	issuerKey, err := client.ObjectKeyFromObject(issuerObj)
	if err != nil {
		return err
	}
	if err := r.Client.Get(context.Background(), issuerKey, issuerObj); err != nil {
		return err
	}
	switch v := issuerObj.(type) {
	case *certmanager.ClusterIssuer:
		if v.Spec.SelfSigned != nil {
			r.selfSignedIssuer = true
			r.caSecretName = r.CertificateSecretName()
			r.caFilename = caCertificateFilename
		}
		if v.Spec.CA != nil {
			return errors.New("controllers: ClusterIssuer.Spec.CA is not supported")
		}
	case *certmanager.Issuer:
		if v.Spec.SelfSigned != nil {
			r.selfSignedIssuer = true
			r.caSecretName = r.CertificateSecretName()
			r.caFilename = caCertificateFilename
		}
		if v.Spec.CA != nil {
			r.selfSignedIssuer = true
			r.caSecretName = v.Spec.CA.SecretName
			r.caFilename = "tls.crt"
		}
	}

	return nil
}
