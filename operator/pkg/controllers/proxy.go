package controllers

import (
	"bytes"
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
	"net/url"
	"sort"

	monitoringv1 "github.com/coreos/prometheus-operator/pkg/apis/monitoring/v1"
	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmClientset "github.com/jetstack/cert-manager/pkg/client/clientset/versioned"
	"golang.org/x/xerrors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	listers "k8s.io/client-go/listers/core/v1"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/operator/pkg/api/etcd"
	etcdv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/etcd/v1alpha1"
	proxyv1 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1"
	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/netutil"
)

const (
	EtcdVersion = "v3.4.7"

	imageRepository            = "quay.io/f110/heimdallr-proxy"
	defaultImageTag            = "latest"
	rpcServerImageRepository   = "quay.io/f110/heimdallr-rpcserver"
	defaultCommand             = "/usr/local/bin/heimdallr-proxy"
	rpcServerCommand           = "/usr/local/bin/heim-rpcserver"
	ctlCommand                 = "/usr/local/bin/heimctl"
	proxyPort                  = 4000
	proxyHttpPort              = 4002
	internalApiPort            = 4004
	dashboardPort              = 4100
	rpcServerPort              = 4001
	rpcMetricsServerPort       = 4005
	configVolumePath           = "/etc/heimdallr"
	configMountPath            = configVolumePath + "/config"
	proxyConfigMountPath       = configVolumePath + "/proxy"
	serverCertMountPath        = configVolumePath + "/certs"
	caCertMountPath            = configVolumePath + "/ca"
	identityProviderSecretPath = configVolumePath + "/idp"
	sessionSecretPath          = configVolumePath + "/session"
	signPrivateKeyPath         = configVolumePath + "/privkey"
	githubSecretPath           = configVolumePath + "/github_secret"
	internalTokenMountPath     = configVolumePath + "/internal_token"
	datastoreCertMountPath     = configVolumePath + "/datastore"

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
	datastoreCAFilename         = "ca.crt"
	datastoreCertFilename       = "client.crt"
	datastoreKeyFilename        = "client.key"

	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

type process struct {
	Deployment          *appsv1.Deployment
	PodDisruptionBudget *policyv1beta1.PodDisruptionBudget
	Service             []*corev1.Service
	ConfigMaps          []*corev1.ConfigMap
	Certificate         *certmanager.Certificate
	ServiceMonitors     []*monitoringv1.ServiceMonitor
}

type HeimdallrProxy struct {
	Name                string
	Namespace           string
	Object              *proxyv1.Proxy
	Spec                proxyv1.ProxySpec
	Datastore           *etcdv1alpha1.EtcdCluster
	CASecret            *corev1.Secret
	SigningPrivateKey   *corev1.Secret
	GithubWebhookSecret *corev1.Secret
	CookieSecret        *corev1.Secret
	InternalTokenSecret *corev1.Secret

	RPCServer       *process
	ProxyServer     *process
	DashboardServer *process

	cmClient      cmClientset.Interface
	serviceLister listers.ServiceLister

	backends         []proxyv1.Backend
	roles            []proxyv1.Role
	rpcPermissions   []proxyv1.RpcPermission
	selfSignedIssuer bool
}

func NewHeimdallrProxy(
	spec *proxyv1.Proxy,
	cmClient cmClientset.Interface, serviceLister listers.ServiceLister,
	backends []proxyv1.Backend, roles []proxyv1.Role, rpcPermissions []proxyv1.RpcPermission) *HeimdallrProxy {
	r := &HeimdallrProxy{
		Name:           spec.Name,
		Namespace:      spec.Namespace,
		Object:         spec,
		Spec:           spec.Spec,
		serviceLister:  serviceLister,
		cmClient:       cmClient,
		backends:       backends,
		roles:          roles,
		rpcPermissions: rpcPermissions,
	}

	found := false
	for _, v := range backends {
		if v.Name == "dashboard" && v.Namespace == spec.Namespace && v.Spec.Layer == "" {
			found = true
			break
		}
	}

	if !found {
		r.backends = append(r.backends, proxyv1.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dashboard",
				Namespace: spec.Namespace,
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

	found = false
	for _, v := range roles {
		if v.Name == "admin" && v.Namespace == r.Namespace {
			found = true
			break
		}
	}
	if !found {
		r.roles = append(r.roles, proxyv1.Role{
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

	found = false
	for _, v := range rpcPermissions {
		if v.Name == "admin" && v.Namespace == r.Namespace {
			found = true
			break
		}
	}
	if !found {
		r.rpcPermissions = append(r.rpcPermissions, proxyv1.RpcPermission{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "admin",
				Namespace: r.Namespace,
			},
			Spec: proxyv1.RpcPermissionSpec{
				Allow: []string{"proxy.rpc.admin.*", "proxy.rpc.certificateauthority.*"},
			},
		})
	}

	return r
}

func (r *HeimdallrProxy) ControlObject(obj metav1.Object) {
	if !metav1.IsControlledBy(obj, r.Object) {
		obj.SetOwnerReferences([]metav1.OwnerReference{*metav1.NewControllerRef(r.Object, proxyv1.SchemeGroupVersion.WithKind("Proxy"))})
	}
}

func (r *HeimdallrProxy) Version() string {
	if r.Spec.Version != "" {
		return r.Spec.Version
	}

	return defaultImageTag
}

func (r *HeimdallrProxy) EtcdClusterName() string {
	return r.Name + "-datastore"
}

func (r *HeimdallrProxy) CertificateSecretName() string {
	return r.Name + "-cert"
}

func (r *HeimdallrProxy) CASecretName() string {
	return r.Name + "-ca"
}

func (r *HeimdallrProxy) PrivateKeySecretName() string {
	return r.Name + "-privkey"
}

func (r *HeimdallrProxy) GithubSecretName() string {
	return r.Name + "-github-secret"
}

func (r *HeimdallrProxy) InternalTokenSecretName() string {
	return r.Name + "-internal-token"
}

func (r *HeimdallrProxy) CookieSecretName() string {
	switch r.Spec.Session.Type {
	case config.SessionTypeSecureCookie:
		return r.Name + "-cookie-secret"
	default:
		return r.Spec.Session.KeySecretRef.Name
	}
}

func (r *HeimdallrProxy) EtcdHost() string {
	return r.EtcdClusterName() + "-client"
}

func (r *HeimdallrProxy) ConfigNameForMain() string {
	return r.Name
}

func (r *HeimdallrProxy) ConfigNameForDashboard() string {
	return r.Name + "-dashboard"
}

func (r *HeimdallrProxy) ConfigNameForRPCServer() string {
	return r.Name + "-rpcserver"
}

func (r *HeimdallrProxy) DeploymentNameForMain() string {
	return r.Name
}

func (r *HeimdallrProxy) PodDisruptionBudgetNameForMain() string {
	return r.Name
}

func (r *HeimdallrProxy) ServiceNameForMain() string {
	return r.Name
}

func (r *HeimdallrProxy) DeploymentNameForDashboard() string {
	return r.Name + "-dashboard"
}

func (r *HeimdallrProxy) DeploymentNameForRPCServer() string {
	return r.Name + "-rpcserver"
}

func (r *HeimdallrProxy) PodDisruptionBudgetNameForDashboard() string {
	return r.Name + "-dashboard"
}

func (r *HeimdallrProxy) PodDisruptionBudgetNameForRPCServer() string {
	return r.Name + "-rpcserver"
}

func (r *HeimdallrProxy) ServiceNameForDashboard() string {
	return r.Name + "-dashboard"
}

func (r *HeimdallrProxy) ServiceNameForRPCServer() string {
	return r.Name + "-rpcserver"
}

func (r *HeimdallrProxy) ReverseProxyConfigName() string {
	return r.Name + "-proxy"
}

func (r *HeimdallrProxy) ServiceNameForInternalApi() string {
	return r.Name + "-internal"
}

func (r *HeimdallrProxy) Backends() []proxyv1.Backend {
	return r.backends
}

func (r *HeimdallrProxy) Roles() []proxyv1.Role {
	return r.roles
}

func (r *HeimdallrProxy) RpcPermissions() []proxyv1.RpcPermission {
	return r.rpcPermissions
}

func (r *HeimdallrProxy) Certificate() *certmanager.Certificate {
	backends := r.Backends()
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

	return &certmanager.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: r.Name, Namespace: r.Namespace},
		Spec: certmanager.CertificateSpec{
			SecretName: r.CertificateSecretName(),
			IssuerRef:  r.Spec.IssuerRef,
			CommonName: r.Spec.Domain,
			DNSNames:   domains,
		},
	}
}

func (r *HeimdallrProxy) EtcdCluster() (*etcdv1alpha1.EtcdCluster, *monitoringv1.PodMonitor) {
	cluster := r.newEtcdCluster()
	return cluster, r.newPodMonitorForEtcdCluster(cluster)
}

func (r *HeimdallrProxy) newEtcdCluster() *etcdv1alpha1.EtcdCluster {
	return &etcdv1alpha1.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.Namespace,
			Name:      r.EtcdClusterName(),
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(r.Object, proxyv1.SchemeGroupVersion.WithKind("Proxy")),
			},
		},
		Spec: etcdv1alpha1.EtcdClusterSpec{
			Members:            3,
			Version:            EtcdVersion,
			DefragmentSchedule: r.Spec.Defragment.Schedule,
		},
	}
}

func (r *HeimdallrProxy) newPodMonitorForEtcdCluster(cluster *etcdv1alpha1.EtcdCluster) *monitoringv1.PodMonitor {
	return &monitoringv1.PodMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: r.Namespace,
			Labels:    r.Spec.Monitor.Labels,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(r.Object, proxyv1.SchemeGroupVersion.WithKind("Proxy")),
			},
		},
		Spec: monitoringv1.PodMonitorSpec{
			JobLabel: "proxy.f110.dev/name",
			Selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					etcd.LabelNameClusterName: cluster.Name,
					etcd.LabelNameRole:        "etcd",
				},
			},
			NamespaceSelector: monitoringv1.NamespaceSelector{
				MatchNames: []string{r.Namespace},
			},
			PodMetricsEndpoints: []monitoringv1.PodMetricsEndpoint{
				{
					TargetPort:  intOrStringFromInt(2379),
					Path:        "/metrics",
					Scheme:      "http",
					HonorLabels: true,
					Interval:    "30s",
				},
			},
		},
	}
}

type CreateSecret struct {
	Name   string
	Known  func() bool
	Create func() (*corev1.Secret, error)
}

func (r *HeimdallrProxy) Secrets() []CreateSecret {
	return []CreateSecret{
		{
			Name:   r.CASecretName(),
			Known:  func() bool { return r.Object.Status.CASecretName != "" },
			Create: r.NewCA,
		},
		{
			Name:   r.PrivateKeySecretName(),
			Known:  func() bool { return r.Object.Status.SigningPrivateKeySecretName != "" },
			Create: r.NewSigningPrivateKey,
		},
		{
			Name:   r.GithubSecretName(),
			Known:  func() bool { return r.Object.Status.GithubWebhookSecretName != "" },
			Create: r.NewGithubSecret,
		},
		{
			Name:   r.CookieSecretName(),
			Known:  func() bool { return r.Object.Status.CookieSecretName != "" },
			Create: r.NewCookieSecret,
		},
		{
			Name:   r.InternalTokenSecretName(),
			Known:  func() bool { return r.Object.Status.InternalTokenSecretName != "" },
			Create: r.NewInternalTokenSecret,
		},
	}
}

func (r *HeimdallrProxy) NewCA() (*corev1.Secret, error) {
	caName := "Heimdallr CA"
	if r.Spec.Name != "" {
		caName = r.Spec.Name
	}
	country := "jp"
	if r.Spec.Country != "" {
		country = r.Spec.Country
	}
	caCert, privateKey, err := cert.CreateCertificateAuthority(caName, r.Spec.Organization, r.Spec.AdministratorUnit, country)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	b, err := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	privKeyBuf := new(bytes.Buffer)
	if err := pem.Encode(privKeyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	certBuf := new(bytes.Buffer)
	if err := pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.CASecretName(),
			Namespace: r.Namespace,
		},
		Data: map[string][]byte{
			caPrivateKeyFilename:  privKeyBuf.Bytes(),
			caCertificateFilename: certBuf.Bytes(),
		},
	}
	r.ControlObject(secret)

	r.CASecret = secret
	return secret, nil
}

func (r *HeimdallrProxy) NewSigningPrivateKey() (*corev1.Secret, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	b, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.PrivateKeySecretName(),
			Namespace: r.Namespace,
		},
		Data: map[string][]byte{
			privateKeyFilename: buf.Bytes(),
		},
	}
	r.ControlObject(secret)

	r.SigningPrivateKey = secret
	return secret, nil
}

func (r *HeimdallrProxy) NewGithubSecret() (*corev1.Secret, error) {
	b := make([]byte, 32)
	for i := range b {
		b[i] = letters[mrand.Intn(len(letters))]
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.GithubSecretName(),
			Namespace: r.Namespace,
		},
		Data: map[string][]byte{
			githubWebhookSecretFilename: b,
		},
	}
	r.ControlObject(secret)

	r.GithubWebhookSecret = secret
	return secret, nil
}

func (r *HeimdallrProxy) NewCookieSecret() (*corev1.Secret, error) {
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

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.CookieSecretName(),
			Namespace: r.Namespace,
		},
		Data: map[string][]byte{
			cookieSecretFilename: buf.Bytes(),
		},
	}
	r.ControlObject(secret)

	r.CookieSecret = secret
	return secret, nil
}

func (r *HeimdallrProxy) NewInternalTokenSecret() (*corev1.Secret, error) {
	b := make([]byte, 32)
	for i := range b {
		b[i] = letters[mrand.Intn(len(letters))]
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.InternalTokenSecretName(),
			Namespace: r.Namespace,
		},
		Data: map[string][]byte{
			internalTokenFilename: b,
		},
	}
	r.ControlObject(secret)

	r.InternalTokenSecret = secret
	return secret, nil
}

func (r *HeimdallrProxy) ConfigForMain() (*corev1.ConfigMap, error) {
	if r.Datastore == nil {
		return nil, WrapRetryError(errors.New("EtcdCluster is not created yet"))
	}

	etcdUrl, err := url.Parse(r.Datastore.Status.ClientEndpoint)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	etcdUrl.Scheme = "etcds"

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
			InternalTokenFile:     fmt.Sprintf("%s/%s", internalTokenMountPath, internalTokenFilename),
			SigningPrivateKeyFile: fmt.Sprintf("%s/%s", signPrivateKeyPath, privateKeyFilename),
		},
		IdentityProvider: &config.IdentityProvider{
			Provider:         r.Spec.IdentityProvider.Provider,
			ClientId:         r.Spec.IdentityProvider.ClientId,
			ClientSecretFile: fmt.Sprintf("%s/%s", identityProviderSecretPath, r.Spec.IdentityProvider.ClientSecretRef.Key),
			ExtraScopes:      []string{"email"},
			RedirectUrl:      r.Spec.IdentityProvider.RedirectUrl,
		},
		Datastore: &config.Datastore{
			RawUrl:     etcdUrl.String(),
			Namespace:  "/heimdallr/",
			CACertFile: fmt.Sprintf("%s/%s", datastoreCertMountPath, datastoreCAFilename),
			CertFile:   fmt.Sprintf("%s/%s", datastoreCertMountPath, datastoreCertFilename),
			KeyFile:    fmt.Sprintf("%s/%s", datastoreCertMountPath, datastoreKeyFilename),
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
		return nil, xerrors.Errorf(": %w", err)
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

func (r *HeimdallrProxy) ConfigForDashboard() (*corev1.ConfigMap, error) {
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
		return nil, xerrors.Errorf(": %w", err)
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

func (r *HeimdallrProxy) ConfigForRPCServer() (*corev1.ConfigMap, error) {
	if r.Datastore == nil {
		return nil, WrapRetryError(errors.New("EtcdCluster is not created yet"))
	}

	etcdUrl, err := url.Parse(r.Datastore.Status.ClientEndpoint)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	etcdUrl.Scheme = "etcds"

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
			RawUrl:     etcdUrl.String(),
			Namespace:  "/heimdallr/",
			CACertFile: fmt.Sprintf("%s/%s", datastoreCertMountPath, datastoreCAFilename),
			CertFile:   fmt.Sprintf("%s/%s", datastoreCertMountPath, datastoreCertFilename),
			KeyFile:    fmt.Sprintf("%s/%s", datastoreCertMountPath, datastoreKeyFilename),
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
		return nil, xerrors.Errorf(": %w", err)
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

func (r *HeimdallrProxy) LabelsForMain() map[string]string {
	return map[string]string{"app": "heimdallr", "proxy.f110.dev/instance": r.Name, "proxy.f110.dev/role": "proxy"}
}

func (r *HeimdallrProxy) LabelsForDashboard() map[string]string {
	return map[string]string{"app": "heimdallr", "proxy.f110.dev/instance": r.Name, "proxy.f110.dev/role": "dashboard"}
}

func (r *HeimdallrProxy) LabelsForRPCServer() map[string]string {
	return map[string]string{"app": "heimdallr", "proxy.f110.dev/instance": r.Name, "proxy.f110.dev/role": "rpcserver"}
}

func (r *HeimdallrProxy) LabelsForDefragmentJob() map[string]string {
	return map[string]string{"app": "heimdallr", "proxy.f110.dev/instance": r.Name, "proxy.f110.dev/role": "job", "proxy.f110.dev/job": "defragment"}
}

func (r *HeimdallrProxy) ReverseProxyConfig() (*corev1.ConfigMap, error) {
	backends := r.Backends()

	proxies := make([]*config.Backend, 0, len(backends))
	backendMap := make(map[string]proxyv1.Backend)
	for _, v := range backends {
		backendMap[v.Namespace+"/"+v.Name] = v

		var service *corev1.Service
		if len(v.Spec.ServiceSelector.MatchLabels) > 0 {
			selector, err := metav1.LabelSelectorAsSelector(&v.Spec.ServiceSelector.LabelSelector)
			if err != nil {
				return nil, xerrors.Errorf(": %w", err)
			}

			services, err := r.serviceLister.Services(r.Spec.BackendSelector.Namespace).List(selector)
			if err != nil {
				return nil, xerrors.Errorf(": %w", err)
			}
			if len(services) == 0 {
				continue
			}

			service = services[0]
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

					upstream = fmt.Sprintf("%s://%s.%s.svc:%d", scheme, service.Name, service.Namespace, p.Port)
					break
				}
			}
		}
		proxies = append(proxies, &config.Backend{
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
		})
	}
	sort.Slice(proxies, func(i, j int) bool {
		return proxies[i].Name < proxies[j].Name
	})
	proxyBinary, err := yaml.Marshal(proxies)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	roleList := r.Roles()
	roles := make([]*config.Role, len(roleList))
	for i, v := range roleList {
		bindings := make([]*config.Binding, 0, len(v.Spec.Bindings))
		for _, b := range v.Spec.Bindings {
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
					continue
				}

				bindings = append(bindings, &config.Binding{
					Permission: b.Permission,
					Backend:    backendHost,
				})
			case b.RpcPermissionName != "":
				bindings = append(bindings, &config.Binding{
					Rpc: b.RpcPermissionName,
				})
			}
		}

		roles[i] = &config.Role{
			Name:        v.Name,
			Title:       v.Spec.Title,
			Description: v.Spec.Description,
			Bindings:    bindings,
		}
	}
	sort.Slice(roles, func(i, j int) bool {
		return roles[i].Name < roles[j].Name
	})
	roleBinary, err := yaml.Marshal(roles)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	rpcPermissionList := r.RpcPermissions()
	rpcPermissions := make([]*config.RpcPermission, len(rpcPermissionList))
	for i, v := range rpcPermissionList {
		rpcPermissions[i] = &config.RpcPermission{
			Name:  v.Name,
			Allow: v.Spec.Allow,
		}
	}
	sort.Slice(rpcPermissions, func(i, j int) bool {
		return rpcPermissions[i].Name < rpcPermissions[j].Name
	})
	rpcPermissionBinary, err := yaml.Marshal(rpcPermissions)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
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

	r.Object.Status.NumOfBackends = len(backends)
	r.Object.Status.NumOfRoles = len(roles)
	r.Object.Status.NumOfRpcPermissions = len(rpcPermissions)
	return configMap, nil
}

func (r *HeimdallrProxy) IdealProxyProcess() (*process, error) {
	if r.Datastore == nil {
		return nil, WrapRetryError(errors.New("EtcdCluster is not created yet"))
	}

	conf, err := r.ConfigForMain()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	confHash := sha256.Sum256([]byte(conf.Data[configFilename]))

	resources := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1"),
			corev1.ResourceMemory: resource.MustParse("256Mi"),
		},
	}
	if r.Spec.ProxyResources != nil {
		resources = *r.Spec.ProxyResources
	}
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
							Name:            "proxy",
							Image:           fmt.Sprintf("%s:%s", imageRepository, r.Version()),
							ImagePullPolicy: corev1.PullAlways,
							Command:         []string{defaultCommand},
							Args:            []string{"-c", fmt.Sprintf("%s/%s", configMountPath, configFilename)},
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
							Resources: resources,
							VolumeMounts: []corev1.VolumeMount{
								{Name: "server-cert", MountPath: serverCertMountPath, ReadOnly: true},
								{Name: "ca-cert", MountPath: caCertMountPath, ReadOnly: true},
								{Name: "signing-priv-key", MountPath: signPrivateKeyPath, ReadOnly: true},
								{Name: "github-secret", MountPath: githubSecretPath, ReadOnly: true},
								{Name: "cookie-secret", MountPath: sessionSecretPath, ReadOnly: true},
								{Name: "config", MountPath: configMountPath, ReadOnly: true},
								{Name: "config-proxy", MountPath: proxyConfigMountPath, ReadOnly: true},
								{Name: "idp-secret", MountPath: identityProviderSecretPath, ReadOnly: true},
								{Name: "internal-token", MountPath: internalTokenMountPath, ReadOnly: true},
								{Name: "datastore-client-cert", MountPath: datastoreCertMountPath, ReadOnly: true},
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
							Name: "signing-priv-key",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: r.PrivateKeySecretName(),
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
						{
							Name: "datastore-client-cert",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: r.Datastore.Status.ClientCertSecretName,
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
			Type:           corev1.ServiceTypeLoadBalancer,
			Selector:       r.LabelsForMain(),
			LoadBalancerIP: r.Spec.LoadBalancerIP,
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
		return nil, xerrors.Errorf(": %w", err)
	}

	serverCert := r.Certificate()

	return &process{
		Deployment:          deployment,
		PodDisruptionBudget: pdb,
		Service:             []*corev1.Service{svc, internalApiSvc},
		ConfigMaps:          []*corev1.ConfigMap{conf, reverseProxyConf},
		Certificate:         serverCert,
	}, nil
}

func (r *HeimdallrProxy) IdealDashboard() (*process, error) {
	if err := r.checkSelfSignedIssuer(); err != nil {
		return nil, xerrors.Errorf(": %w", err)
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
		return nil, xerrors.Errorf(": %w", err)
	}
	confHash := sha256.Sum256([]byte(conf.Data[configFilename]))

	replicas := r.Spec.DashboardReplicas
	if replicas == 0 {
		replicas = 3 // This is default value of DashboardReplicas.
	}
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
							Name:            "proxy",
							Image:           fmt.Sprintf("%s:%s", imageRepository, r.Version()),
							ImagePullPolicy: corev1.PullAlways,
							Command:         []string{defaultCommand},
							Args:            []string{"-c", fmt.Sprintf("%s/%s", configMountPath, configFilename)},
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
									corev1.ResourceCPU:    resource.MustParse("10m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
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

	return &process{
		Deployment:          deployment,
		PodDisruptionBudget: pdb,
		Service:             []*corev1.Service{svc},
		ConfigMaps:          []*corev1.ConfigMap{conf},
	}, nil
}

func (r *HeimdallrProxy) IdealRPCServer() (*process, error) {
	if r.Datastore == nil {
		return nil, WrapRetryError(errors.New("EtcdCluster is not created yet"))
	}

	conf, err := r.ConfigForRPCServer()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	confHash := sha256.Sum256([]byte(conf.Data[configFilename]))

	resources := corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1"),
			corev1.ResourceMemory: resource.MustParse("256Mi"),
		},
	}
	if r.Spec.RPCServerResources != nil {
		resources = *r.Spec.RPCServerResources
	}
	var replicas int32 = 2
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.DeploymentNameForRPCServer(),
			Namespace: r.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(r.Object, proxyv1.SchemeGroupVersion.WithKind("Proxy")),
			},
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
							Name:            "rpcserver",
							Image:           fmt.Sprintf("%s:%s", rpcServerImageRepository, r.Version()),
							ImagePullPolicy: corev1.PullAlways,
							Command:         []string{rpcServerCommand},
							Args:            []string{"-c", fmt.Sprintf("%s/%s", configMountPath, configFilename)},
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
							Resources: resources,
							VolumeMounts: []corev1.VolumeMount{
								{Name: "ca-cert", MountPath: caCertMountPath, ReadOnly: true},
								{Name: "privatekey", MountPath: signPrivateKeyPath, ReadOnly: true},
								{Name: "config", MountPath: configMountPath, ReadOnly: true},
								{Name: "config-proxy", MountPath: proxyConfigMountPath, ReadOnly: true},
								{Name: "internal-token", MountPath: internalTokenMountPath, ReadOnly: true},
								{Name: "datastore-client-cert", MountPath: datastoreCertMountPath, ReadOnly: true},
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
						{
							Name: "datastore-client-cert",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: r.Datastore.Status.ClientCertSecretName,
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

	reverseProxyConf, err := r.ReverseProxyConfig()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
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

	minAvailable := intstr.FromInt(1)
	pdb := &policyv1beta1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.PodDisruptionBudgetNameForRPCServer(),
			Namespace: r.Namespace,
		},
		Spec: policyv1beta1.PodDisruptionBudgetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: r.LabelsForRPCServer(),
			},
			MinAvailable: &minAvailable,
		},
	}

	return &process{
		Deployment:          deployment,
		PodDisruptionBudget: pdb,
		Service:             []*corev1.Service{svc},
		ConfigMaps:          []*corev1.ConfigMap{conf, reverseProxyConf},
		ServiceMonitors:     []*monitoringv1.ServiceMonitor{rpcMetrics},
	}, nil
}

func (r *HeimdallrProxy) checkSelfSignedIssuer() error {
	var issuerObj runtime.Object
	switch r.Spec.IssuerRef.Kind {
	case certmanager.ClusterIssuerKind:
		ci, err := r.cmClient.CertmanagerV1alpha2().ClusterIssuers().Get(r.Spec.IssuerRef.Name, metav1.GetOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		issuerObj = ci
	case certmanager.IssuerKind:
		ci, err := r.cmClient.CertmanagerV1alpha2().Issuers(r.Namespace).Get(r.Spec.IssuerRef.Name, metav1.GetOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		issuerObj = ci
	}

	switch v := issuerObj.(type) {
	case *certmanager.ClusterIssuer:
		if v.Spec.SelfSigned != nil {
			r.selfSignedIssuer = true
		}
		if v.Spec.CA != nil {
			return errors.New("controllers: ClusterIssuer.Spec.NewCA is not supported")
		}
	case *certmanager.Issuer:
		if v.Spec.SelfSigned != nil {
			r.selfSignedIssuer = true
		}
		if v.Spec.CA != nil {
			r.selfSignedIssuer = true
		}
	}

	return nil
}

func intOrStringFromInt(val int) *intstr.IntOrString {
	v := intstr.FromInt(val)
	return &v
}
