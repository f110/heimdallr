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
	"net/url"
	"sort"

	certmanagerv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	certmanagerv1alpha2 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	certmanagerv1alpha3 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha3"
	certmanagerv1beta1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1beta1"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"golang.org/x/xerrors"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	listers "k8s.io/client-go/listers/core/v1"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/k8s/api/etcd"
	etcdv1alpha2 "go.f110.dev/heimdallr/pkg/k8s/api/etcd/v1alpha2"
	proxyv1alpha2 "go.f110.dev/heimdallr/pkg/k8s/api/proxy/v1alpha2"
	clientset "go.f110.dev/heimdallr/pkg/k8s/client/versioned"
	"go.f110.dev/heimdallr/pkg/k8s/client/versioned/scheme"
	"go.f110.dev/heimdallr/pkg/k8s/controllers/controllerbase"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
	"go.f110.dev/heimdallr/pkg/netutil"
	"go.f110.dev/heimdallr/pkg/rpc"
)

const (
	EtcdVersion = "v3.4.8"

	ProxyImageRepository       = "quay.io/f110/heimdallr-proxy"
	defaultImageTag            = "latest"
	RPCServerImageRepository   = "quay.io/f110/heimdallr-rpcserver"
	DashboardImageRepository   = "quay.io/f110/heimdallr-dashboard"
	defaultCommand             = "/usr/local/bin/heimdallr-proxy"
	rpcServerCommand           = "/usr/local/bin/heim-rpcserver"
	dashboardCommand           = "/usr/local/bin/heim-dashboard"
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

	labelKeyVirtualDashboard = "virtual.dashboard"
)

type process struct {
	Deployment          *appsv1.Deployment
	PodDisruptionBudget *policyv1.PodDisruptionBudget
	Service             []*corev1.Service
	ConfigMaps          []*corev1.ConfigMap
	Certificate         runtime.Object
	ServiceMonitors     []*monitoringv1.ServiceMonitor
}

type HeimdallrProxy struct {
	Name                      string
	Namespace                 string
	Object                    *proxyv1alpha2.Proxy
	Spec                      proxyv1alpha2.ProxySpec
	Datastore                 *etcdv1alpha2.EtcdCluster
	CASecret                  *corev1.Secret
	SigningPrivateKey         *corev1.Secret
	GithubWebhookSecret       *corev1.Secret
	CookieSecret              *corev1.Secret
	InternalTokenSecret       *corev1.Secret
	ServerCertSecret          *corev1.Secret
	IdentityProviderSecret    *corev1.Secret
	DatastoreClientCertSecret *corev1.Secret

	RPCServer       *process
	ProxyServer     *process
	DashboardServer *process

	clientset     clientset.Interface
	serviceLister listers.ServiceLister

	backends           []*proxyv1alpha2.Backend
	roles              []*proxyv1alpha2.Role
	rpcPermissions     []*proxyv1alpha2.RpcPermission
	roleBindings       []*proxyv1alpha2.RoleBinding
	selfSignedIssuer   bool
	certManagerVersion string
}

type HeimdallrProxyParams struct {
	Spec               *proxyv1alpha2.Proxy
	Clientset          clientset.Interface
	ServiceLister      listers.ServiceLister
	Backends           []*proxyv1alpha2.Backend
	Roles              []*proxyv1alpha2.Role
	RpcPermissions     []*proxyv1alpha2.RpcPermission
	RoleBindings       []*proxyv1alpha2.RoleBinding
	CertManagerVersion string
}

func NewHeimdallrProxy(opt HeimdallrProxyParams) *HeimdallrProxy {
	r := &HeimdallrProxy{
		Name:               opt.Spec.Name,
		Namespace:          opt.Spec.Namespace,
		Object:             opt.Spec,
		Spec:               opt.Spec.Spec,
		serviceLister:      opt.ServiceLister,
		clientset:          opt.Clientset,
		backends:           opt.Backends,
		roles:              opt.Roles,
		rpcPermissions:     opt.RpcPermissions,
		roleBindings:       opt.RoleBindings,
		certManagerVersion: opt.CertManagerVersion,
	}

	found := false
	for _, v := range opt.Backends {
		if v.Name == "dashboard" && v.Namespace == opt.Spec.Namespace && v.Spec.Layer == "" {
			found = true
			break
		}
	}

	if !found {
		r.backends = append(r.backends, &proxyv1alpha2.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dashboard",
				Namespace: opt.Spec.Namespace,
				Labels: map[string]string{
					labelKeyVirtualDashboard: "yes",
				},
			},
			Spec: proxyv1alpha2.BackendSpec{
				AllowRootUser: true,
				HTTP: []*proxyv1alpha2.BackendHTTPSpec{
					{
						Path:     "/",
						Upstream: fmt.Sprintf("http://%s:%d", r.ServiceNameForDashboard(), dashboardPort),
					},
				},
				Permissions: []proxyv1alpha2.Permission{
					{
						Name: "all",
						Locations: []proxyv1alpha2.Location{
							{Any: "/"},
						},
					},
				},
			},
		})
	}

	found = false
	for _, v := range opt.Roles {
		if v.Name == "admin" && v.Namespace == r.Namespace {
			found = true
			break
		}
	}
	if !found {
		r.roles = append(r.roles, &proxyv1alpha2.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "admin",
				Namespace: r.Namespace,
			},
			Spec: proxyv1alpha2.RoleSpec{
				Title:          "administrator",
				Description:    fmt.Sprintf("%s administrators", r.Name),
				AllowDashboard: true,
			},
		})
	}

	found = false
	for _, v := range opt.RpcPermissions {
		if v.Name == "admin" && v.Namespace == r.Namespace {
			found = true
			break
		}
	}
	if !found {
		r.rpcPermissions = append(r.rpcPermissions, &proxyv1alpha2.RpcPermission{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "admin",
				Namespace: r.Namespace,
			},
			Spec: proxyv1alpha2.RpcPermissionSpec{
				Allow: []string{"proxy.rpc.admin.*", "proxy.rpc.certificateauthority.*"},
			},
		})
	}

	return r
}

func (r *HeimdallrProxy) Init(secretLister listers.SecretLister) error {
	caSecret, err := secretLister.Secrets(r.Namespace).Get(r.CASecretName())
	if err == nil {
		r.CASecret = caSecret
	}
	privateKeySecret, err := secretLister.Secrets(r.Namespace).Get(r.PrivateKeySecretName())
	if err == nil {
		r.SigningPrivateKey = privateKeySecret
	}
	githubSecret, err := secretLister.Secrets(r.Namespace).Get(r.GithubSecretName())
	if err == nil {
		r.GithubWebhookSecret = githubSecret
	}
	cookieSecret, err := secretLister.Secrets(r.Namespace).Get(r.CookieSecretName())
	if err == nil {
		r.CookieSecret = cookieSecret
	}
	internalTokenSecret, err := secretLister.Secrets(r.Namespace).Get(r.InternalTokenSecretName())
	if err == nil {
		r.InternalTokenSecret = internalTokenSecret
	}
	serverCertSecret, err := secretLister.Secrets(r.Namespace).Get(r.CertificateSecretName())
	if err == nil {
		r.ServerCertSecret = serverCertSecret
	}
	idpSecret, err := secretLister.Secrets(r.Namespace).Get(r.Spec.IdentityProvider.ClientSecretRef.Name)
	if err == nil {
		r.IdentityProviderSecret = idpSecret
	}
	if r.Datastore != nil && r.Datastore.Status.ClientCertSecretName != "" {
		datastoreClientCertSecret, err := secretLister.Secrets(r.Namespace).Get(r.Datastore.Status.ClientCertSecretName)
		if err == nil {
			r.DatastoreClientCertSecret = datastoreClientCertSecret
		}
	}

	return nil
}

func (r *HeimdallrProxy) ControlObject(obj metav1.Object) {
	if !metav1.IsControlledBy(obj, r.Object) {
		obj.SetOwnerReferences([]metav1.OwnerReference{*metav1.NewControllerRef(r.Object, proxyv1alpha2.SchemeGroupVersion.WithKind("Proxy"))})
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

func (r *HeimdallrProxy) Backends() []*proxyv1alpha2.Backend {
	return r.backends
}

func (r *HeimdallrProxy) Roles() []*proxyv1alpha2.Role {
	return r.roles
}

func (r *HeimdallrProxy) RoleBindings() []*proxyv1alpha2.RoleBinding {
	return r.roleBindings
}

func (r *HeimdallrProxy) RpcPermissions() []*proxyv1alpha2.RpcPermission {
	return r.rpcPermissions
}

func (r *HeimdallrProxy) Certificate() runtime.Object {
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

	switch r.certManagerVersion {
	case "v1alpha2":
		return &certmanagerv1alpha2.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: r.Name, Namespace: r.Namespace},
			Spec: certmanagerv1alpha2.CertificateSpec{
				SecretName: r.CertificateSecretName(),
				IssuerRef:  r.Spec.IssuerRef,
				CommonName: r.Spec.Domain,
				DNSNames:   domains,
			},
		}
	case "v1alpha3":
		return &certmanagerv1alpha3.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: r.Name, Namespace: r.Namespace},
			Spec: certmanagerv1alpha3.CertificateSpec{
				SecretName: r.CertificateSecretName(),
				IssuerRef:  r.Spec.IssuerRef,
				CommonName: r.Spec.Domain,
				DNSNames:   domains,
			},
		}
	case "v1beta1":
		return &certmanagerv1beta1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: r.Name, Namespace: r.Namespace},
			Spec: certmanagerv1beta1.CertificateSpec{
				SecretName: r.CertificateSecretName(),
				IssuerRef:  r.Spec.IssuerRef,
				CommonName: r.Spec.Domain,
				DNSNames:   domains,
			},
		}
	default: // v1
		return &certmanagerv1.Certificate{
			ObjectMeta: metav1.ObjectMeta{Name: r.Name, Namespace: r.Namespace},
			Spec: certmanagerv1.CertificateSpec{
				SecretName: r.CertificateSecretName(),
				IssuerRef:  r.Spec.IssuerRef,
				CommonName: r.Spec.Domain,
				DNSNames:   domains,
			},
		}
	}

	return nil
}

func (r *HeimdallrProxy) EtcdCluster() (*etcdv1alpha2.EtcdCluster, *monitoringv1.PodMonitor) {
	cluster := r.newEtcdCluster()
	return cluster, r.newPodMonitorForEtcdCluster(cluster)
}

func (r *HeimdallrProxy) newEtcdCluster() *etcdv1alpha2.EtcdCluster {
	etcdVersion := EtcdVersion
	if r.Spec.DataStore != nil && r.Spec.DataStore.Etcd != nil && r.Spec.DataStore.Etcd.Version != "" {
		etcdVersion = r.Spec.DataStore.Etcd.Version
	}

	ec := etcd.Factory(nil,
		k8sfactory.Name(r.EtcdClusterName()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.ControlledBy(r.Object, scheme.Scheme),
		etcd.Member(3),
		etcd.Version(etcdVersion),
	)
	if r.Spec.DataStore != nil && r.Spec.DataStore.Etcd != nil {
		ec = etcd.Factory(ec, etcd.DefragmentSchedule(r.Spec.DataStore.Etcd.Defragment.Schedule))
		if r.Spec.AntiAffinity {
			ec = etcd.Factory(ec, etcd.EnableAntiAffinity)
		}

		if r.Spec.DataStore.Etcd.Backup != nil {
			ec = etcd.Factory(ec, etcd.Backup(r.Spec.DataStore.Etcd.Backup.IntervalInSecond, r.Spec.DataStore.Etcd.Backup.MaxBackups))

			switch {
			case r.Spec.DataStore.Etcd.Backup.Storage.MinIO != nil:
				ec = etcd.Factory(ec,
					etcd.BackupToMinIO(
						r.Spec.DataStore.Etcd.Backup.Storage.MinIO.Bucket,
						r.Spec.DataStore.Etcd.Backup.Storage.MinIO.Path,
						r.Spec.DataStore.Etcd.Backup.Storage.MinIO.Secure,
						r.Spec.DataStore.Etcd.Backup.Storage.MinIO.ServiceSelector.Name,
						r.Spec.DataStore.Etcd.Backup.Storage.MinIO.ServiceSelector.Namespace,
						etcdv1alpha2.AWSCredentialSelector{
							Name:               r.Spec.DataStore.Etcd.Backup.Storage.MinIO.CredentialSelector.Name,
							Namespace:          r.Spec.DataStore.Etcd.Backup.Storage.MinIO.CredentialSelector.Namespace,
							AccessKeyIDKey:     r.Spec.DataStore.Etcd.Backup.Storage.MinIO.CredentialSelector.AccessKeyIDKey,
							SecretAccessKeyKey: r.Spec.DataStore.Etcd.Backup.Storage.MinIO.CredentialSelector.SecretAccessKeyKey,
						},
					),
				)
			case r.Spec.DataStore.Etcd.Backup.Storage.GCS != nil:
				ec = etcd.Factory(ec,
					etcd.BackupToGCS(
						r.Spec.DataStore.Etcd.Backup.Storage.GCS.Bucket,
						r.Spec.DataStore.Etcd.Backup.Storage.GCS.Path,
						etcdv1alpha2.GCPCredentialSelector{
							Name:                  r.Spec.DataStore.Etcd.Backup.Storage.GCS.CredentialSelector.Name,
							Namespace:             r.Spec.DataStore.Etcd.Backup.Storage.GCS.CredentialSelector.Namespace,
							ServiceAccountJSONKey: r.Spec.DataStore.Etcd.Backup.Storage.GCS.CredentialSelector.ServiceAccountJSONKey,
						},
					),
				)
			}
		}
	}

	return ec
}

func (r *HeimdallrProxy) newPodMonitorForEtcdCluster(cluster *etcdv1alpha2.EtcdCluster) *monitoringv1.PodMonitor {
	return &monitoringv1.PodMonitor{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cluster.Name,
			Namespace: r.Namespace,
			Labels:    r.Spec.Monitor.Labels,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(r.Object, proxyv1alpha2.SchemeGroupVersion.WithKind("Proxy")),
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
					Port:        "metrics",
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
	country := "jp"
	organization := ""
	administratorUnit := ""
	if r.Spec.CertificateAuthority != nil {
		if r.Spec.CertificateAuthority.Local != nil {
			if r.Spec.CertificateAuthority.Local.Name != "" {
				caName = r.Spec.CertificateAuthority.Local.Name
			}
			if r.Spec.CertificateAuthority.Local.Country != "" {
				country = r.Spec.CertificateAuthority.Local.Country
			}
			if r.Spec.CertificateAuthority.Local.Organization != "" {
				organization = r.Spec.CertificateAuthority.Local.Organization
			}
			if r.Spec.CertificateAuthority.Local.AdministratorUnit != "" {
				administratorUnit = r.Spec.CertificateAuthority.Local.AdministratorUnit
			}
		}
	}

	caCert, privateKey, err := cert.CreateCertificateAuthority(caName, organization, administratorUnit, country, "ecdsa")
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

	secret := k8sfactory.SecretFactory(nil,
		k8sfactory.Name(r.CASecretName()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.Data(caPrivateKeyFilename, privKeyBuf.Bytes()),
		k8sfactory.Data(caCertificateFilename, certBuf.Bytes()),
	)

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

	secret := k8sfactory.SecretFactory(nil,
		k8sfactory.Name(r.PrivateKeySecretName()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.Data(privateKeyFilename, buf.Bytes()),
	)

	r.SigningPrivateKey = secret
	return secret, nil
}

func (r *HeimdallrProxy) NewGithubSecret() (*corev1.Secret, error) {
	b := make([]byte, 32)
	for i := range b {
		b[i] = letters[mrand.Intn(len(letters))]
	}

	secret := k8sfactory.SecretFactory(nil,
		k8sfactory.Name(r.GithubSecretName()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.Data(githubWebhookSecretFilename, b),
	)

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

	secret := k8sfactory.SecretFactory(nil,
		k8sfactory.Name(r.CookieSecretName()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.Data(cookieSecretFilename, buf.Bytes()),
	)

	r.CookieSecret = secret
	return secret, nil
}

func (r *HeimdallrProxy) NewInternalTokenSecret() (*corev1.Secret, error) {
	b := make([]byte, 32)
	for i := range b {
		b[i] = letters[mrand.Intn(len(letters))]
	}
	secret := k8sfactory.SecretFactory(nil,
		k8sfactory.Name(r.InternalTokenSecretName()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.Data(internalTokenFilename, b),
	)

	r.InternalTokenSecret = secret
	return secret, nil
}

func (r *HeimdallrProxy) ConfigForMain() (*corev1.ConfigMap, error) {
	if r.Datastore == nil {
		return nil, controllerbase.WrapRetryError(errors.New("EtcdCluster is not created yet"))
	}

	etcdUrl, err := url.Parse(r.Datastore.Status.ClientEndpoint)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	etcdUrl.Scheme = "etcds"

	logLevel := "info"
	if r.Spec.Development {
		logLevel = "debug"
	}
	conf := &configv2.Config{
		AccessProxy: &configv2.AccessProxy{
			HTTP: &configv2.AuthProxyHTTP{
				Bind:       fmt.Sprintf(":%d", proxyPort),
				ServerName: r.Spec.Domain,
				Certificate: &configv2.Certificate{
					CertFile: fmt.Sprintf("%s/%s", serverCertMountPath, serverCertificateFilename),
					KeyFile:  fmt.Sprintf("%s/%s", serverCertMountPath, serverPrivateKeyFilename),
				},
				ExpectCT: true,
				Session: &configv2.Session{
					Type:    r.Spec.Session.Type,
					KeyFile: fmt.Sprintf("%s/%s", sessionSecretPath, cookieSecretFilename),
				},
			},
			RPCServer: fmt.Sprintf("%s:%d", r.ServiceNameForRPCServer(), rpcServerPort),
			ProxyFile: fmt.Sprintf("%s/%s", proxyConfigMountPath, proxyFilename),
			Credential: &configv2.Credential{
				InternalTokenFile:       fmt.Sprintf("%s/%s", internalTokenMountPath, internalTokenFilename),
				SigningPrivateKeyFile:   fmt.Sprintf("%s/%s", signPrivateKeyPath, privateKeyFilename),
				GithubWebHookSecretFile: fmt.Sprintf("%s/%s", githubSecretPath, githubWebhookSecretFilename),
			},
		},
		AuthorizationEngine: &configv2.AuthorizationEngine{
			RoleFile:          fmt.Sprintf("%s/%s", proxyConfigMountPath, roleFilename),
			RPCPermissionFile: fmt.Sprintf("%s/%s", proxyConfigMountPath, rpcPermissionFilename),
			RootUsers:         r.Spec.RootUsers,
		},
		CertificateAuthority: &configv2.CertificateAuthority{},
		IdentityProvider: &configv2.IdentityProvider{
			Provider:         r.Spec.IdentityProvider.Provider,
			ClientId:         r.Spec.IdentityProvider.ClientId,
			ClientSecretFile: fmt.Sprintf("%s/%s", identityProviderSecretPath, r.Spec.IdentityProvider.ClientSecretRef.Key),
			ExtraScopes:      []string{"email"},
			RedirectUrl:      r.Spec.IdentityProvider.RedirectUrl,
		},
		Datastore: &configv2.Datastore{
			DatastoreEtcd: &configv2.DatastoreEtcd{
				RawUrl:     etcdUrl.String(),
				Namespace:  "/heimdallr/",
				CACertFile: fmt.Sprintf("%s/%s", datastoreCertMountPath, datastoreCAFilename),
				CertFile:   fmt.Sprintf("%s/%s", datastoreCertMountPath, datastoreCertFilename),
				KeyFile:    fmt.Sprintf("%s/%s", datastoreCertMountPath, datastoreKeyFilename),
			},
		},
		Logger: &configv2.Logger{
			Level:    logLevel,
			Encoding: "console",
		},
		Dashboard: &configv2.Dashboard{},
	}
	if r.Spec.HttpPort != 0 {
		conf.AccessProxy.HTTP.BindHttp = fmt.Sprintf(":%d", proxyHttpPort)
	}
	if r.Spec.CertificateAuthority != nil && r.Spec.CertificateAuthority.Local != nil {
		conf.CertificateAuthority.Local = &configv2.CertificateAuthorityLocal{
			CertFile: fmt.Sprintf("%s/%s", caCertMountPath, caCertificateFilename),
		}
	}
	if r.Spec.CertificateAuthority != nil && r.Spec.CertificateAuthority.Vault != nil {
		conf.CertificateAuthority.Vault = &configv2.CertificateAuthorityVault{
			Addr:  r.Spec.CertificateAuthority.Vault.Addr,
			Token: r.Spec.CertificateAuthority.Vault.Token,
			Role:  r.Spec.CertificateAuthority.Vault.Role,
		}
	}
	b, err := yaml.Marshal(conf)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	configMap := k8sfactory.ConfigMapFactory(nil,
		k8sfactory.Name(r.ConfigNameForMain()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.Data(configFilename, b),
	)

	return configMap, nil
}

func (r *HeimdallrProxy) ConfigForDashboard() (*corev1.ConfigMap, error) {
	logLevel := "info"
	if r.Spec.Development {
		logLevel = "debug"
	}
	conf := &configv2.Config{
		Logger: &configv2.Logger{
			Level:    logLevel,
			Encoding: "json",
		},
		CertificateAuthority: &configv2.CertificateAuthority{},
		Dashboard: &configv2.Dashboard{
			Bind:         fmt.Sprintf(":%d", dashboardPort),
			RPCServer:    fmt.Sprintf("%s:%d", r.ServiceNameForRPCServer(), rpcServerPort),
			TokenFile:    fmt.Sprintf("%s/%s", internalTokenMountPath, internalTokenFilename),
			PublicKeyUrl: fmt.Sprintf("http://%s.%s.svc:%d/internal/publickey", r.ServiceNameForInternalApi(), r.Namespace, internalApiPort),
		},
	}
	if r.Spec.CertificateAuthority != nil && r.Spec.CertificateAuthority.Local != nil {
		conf.CertificateAuthority.Local = &configv2.CertificateAuthorityLocal{
			CertFile: fmt.Sprintf("%s/%s", caCertMountPath, caCertificateFilename),
		}
	}
	if r.Spec.CertificateAuthority != nil && r.Spec.CertificateAuthority.Vault != nil {
		conf.CertificateAuthority.Vault = &configv2.CertificateAuthorityVault{
			Addr:  r.Spec.CertificateAuthority.Vault.Addr,
			Token: r.Spec.CertificateAuthority.Vault.Token,
			Role:  r.Spec.CertificateAuthority.Vault.Role,
		}
	}

	b, err := yaml.Marshal(conf)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	configMap := k8sfactory.ConfigMapFactory(nil,
		k8sfactory.Name(r.ConfigNameForDashboard()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.Data(configFilename, b),
	)

	return configMap, nil
}

func (r *HeimdallrProxy) ConfigForRPCServer() (*corev1.ConfigMap, error) {
	if r.Datastore == nil {
		return nil, controllerbase.WrapRetryError(errors.New("EtcdCluster is not created yet"))
	}

	etcdUrl, err := url.Parse(r.Datastore.Status.ClientEndpoint)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	etcdUrl.Scheme = "etcds"

	logLevel := "info"
	if r.Spec.Development {
		logLevel = "debug"
	}
	conf := &configv2.Config{
		AccessProxy: &configv2.AccessProxy{
			ProxyFile: fmt.Sprintf("%s/%s", proxyConfigMountPath, proxyFilename),
			HTTP: &configv2.AuthProxyHTTP{
				ServerName: r.Spec.Domain,
			},
			Credential: &configv2.Credential{
				SigningPrivateKeyFile: fmt.Sprintf("%s/%s", signPrivateKeyPath, privateKeyFilename),
				InternalTokenFile:     fmt.Sprintf("%s/%s", internalTokenMountPath, internalTokenFilename),
			},
		},
		Logger: &configv2.Logger{
			Level:    logLevel,
			Encoding: "console",
		},
		AuthorizationEngine: &configv2.AuthorizationEngine{
			RoleFile:          fmt.Sprintf("%s/%s", proxyConfigMountPath, roleFilename),
			RPCPermissionFile: fmt.Sprintf("%s/%s", proxyConfigMountPath, rpcPermissionFilename),
			RootUsers:         r.Spec.RootUsers,
		},
		CertificateAuthority: &configv2.CertificateAuthority{
			Local: &configv2.CertificateAuthorityLocal{},
		},
		Datastore: &configv2.Datastore{
			DatastoreEtcd: &configv2.DatastoreEtcd{
				RawUrl:     etcdUrl.String(),
				Namespace:  "/heimdallr/",
				CACertFile: fmt.Sprintf("%s/%s", datastoreCertMountPath, datastoreCAFilename),
				CertFile:   fmt.Sprintf("%s/%s", datastoreCertMountPath, datastoreCertFilename),
				KeyFile:    fmt.Sprintf("%s/%s", datastoreCertMountPath, datastoreKeyFilename),
			},
		},
		RPCServer: &configv2.RPCServer{
			Bind: fmt.Sprintf(":%d", rpcServerPort),
		},
	}
	if r.Spec.CertificateAuthority != nil && r.Spec.CertificateAuthority.Local != nil {
		conf.CertificateAuthority.Local = &configv2.CertificateAuthorityLocal{
			CertFile:         fmt.Sprintf("%s/%s", caCertMountPath, caCertificateFilename),
			KeyFile:          fmt.Sprintf("%s/%s", caCertMountPath, caPrivateKeyFilename),
			Organization:     r.Spec.CertificateAuthority.Local.Organization,
			OrganizationUnit: r.Spec.CertificateAuthority.Local.AdministratorUnit,
			Country:          r.Spec.CertificateAuthority.Local.Country,
		}
	}
	if r.Spec.CertificateAuthority != nil && r.Spec.CertificateAuthority.Vault != nil {
		conf.CertificateAuthority.Vault = &configv2.CertificateAuthorityVault{
			Addr:  r.Spec.CertificateAuthority.Vault.Addr,
			Token: r.Spec.CertificateAuthority.Vault.Token,
			Role:  r.Spec.CertificateAuthority.Vault.Role,
		}
	}
	if r.Spec.Monitor.PrometheusMonitoring {
		conf.RPCServer.MetricsBind = fmt.Sprintf(":%d", rpcMetricsServerPort)
	}

	b, err := yaml.Marshal(conf)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	configMap := k8sfactory.ConfigMapFactory(nil,
		k8sfactory.Name(r.ConfigNameForRPCServer()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.Data(configFilename, b),
	)

	return configMap, nil
}

func (r *HeimdallrProxy) LabelsForMain() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "heimdallr",
		"app.kubernetes.io/instance":  r.Name,
		"app.kubernetes.io/component": "proxy",
	}
}

func (r *HeimdallrProxy) LabelsForDashboard() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "heimdallr",
		"app.kubernetes.io/instance":  r.Name,
		"app.kubernetes.io/component": "dashboard",
	}
}

func (r *HeimdallrProxy) LabelsForRPCServer() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "heimdallr",
		"app.kubernetes.io/instance":  r.Name,
		"app.kubernetes.io/component": "rpcserver",
	}
}

func (r *HeimdallrProxy) LabelsForDefragmentJob() map[string]string {
	return map[string]string{
		"app.kubernetes.io/name":      "heimdallr",
		"app.kubernetes.io/instance":  r.Name,
		"app.kubernetes.io/component": "defragment",
	}
}

func (r *HeimdallrProxy) ReverseProxyConfig() (*corev1.ConfigMap, error) {
	proxyBinary, err := ConfigConverter{}.Proxy(r.Backends(), r.serviceLister)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	roleBinary, err := ConfigConverter{}.Role(r.Backends(), r.Roles(), r.RoleBindings())
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	rpcPermissionBinary, err := ConfigConverter{}.RPCPermission(r.RpcPermissions())
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	configMap := k8sfactory.ConfigMapFactory(nil,
		k8sfactory.Name(r.ReverseProxyConfigName()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.Data(roleFilename, roleBinary),
		k8sfactory.Data(proxyFilename, proxyBinary),
		k8sfactory.Data(rpcPermissionFilename, rpcPermissionBinary),
	)

	r.Object.Status.NumOfBackends = len(r.Backends())
	r.Object.Status.NumOfRoles = len(r.Roles())
	r.Object.Status.NumOfRpcPermissions = len(r.RpcPermissions())
	return configMap, nil
}

func (r *HeimdallrProxy) IdealProxyProcess() (*process, error) {
	if r.Datastore == nil {
		return nil, controllerbase.WrapRetryError(errors.New("EtcdCluster is not created yet"))
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

	caVolume := k8sfactory.NewSecretVolumeSource(
		"ca-cert",
		caCertMountPath,
		r.CASecret,
		corev1.KeyToPath{Key: caCertificateFilename, Path: caCertificateFilename},
	)
	serverCertVolume := k8sfactory.NewSecretVolumeSource("server-cert", serverCertMountPath, r.ServerCertSecret)
	signingPrivateKeyVolume := k8sfactory.NewSecretVolumeSource("signing-priv-key", signPrivateKeyPath, r.SigningPrivateKey)
	githubSecretVolume := k8sfactory.NewSecretVolumeSource("github-secret", githubSecretPath, r.GithubWebhookSecret)
	cookieSecretVolume := k8sfactory.NewSecretVolumeSource("cookie-secret", sessionSecretPath, r.CookieSecret)
	configVolume := k8sfactory.NewConfigMapVolumeSource("config", configMountPath, r.ConfigNameForMain())
	configProxyVolume := k8sfactory.NewConfigMapVolumeSource("config-proxy", proxyConfigMountPath, r.ReverseProxyConfigName())
	idpSecretVolume := k8sfactory.NewSecretVolumeSource("idp-secret", identityProviderSecretPath, r.IdentityProviderSecret)
	internalTokenVolume := k8sfactory.NewSecretVolumeSource("internal-token", internalTokenMountPath, r.InternalTokenSecret)
	datastoreClientCertVolume := k8sfactory.NewSecretVolumeSource("datastore-client-cert", datastoreCertMountPath, r.DatastoreClientCertSecret)
	proxyContainer := k8sfactory.ContainerFactory(nil,
		k8sfactory.Name("proxy"),
		k8sfactory.Image(fmt.Sprintf("%s:%s", ProxyImageRepository, r.Version()), []string{defaultCommand}),
		k8sfactory.Args("-c", fmt.Sprintf("%s/%s", configMountPath, configFilename)),
		k8sfactory.ReadinessProbe(k8sfactory.HTTPProbe(internalApiPort, "/readiness")),
		k8sfactory.LivenessProbe(k8sfactory.HTTPProbe(internalApiPort, "/liveness")),
		k8sfactory.EnvFromField(netutil.IPAddressEnvKey, "status.podIP"),
		k8sfactory.EnvFromField(netutil.NamespaceEnvKey, "metadata.namespace"),
		k8sfactory.Port("https", corev1.ProtocolTCP, proxyPort),
		k8sfactory.Port("internal", corev1.ProtocolTCP, internalApiPort),
		k8sfactory.Requests(resources.Requests),
		k8sfactory.Limits(resources.Limits),
		k8sfactory.Volume(caVolume),
		k8sfactory.Volume(serverCertVolume),
		k8sfactory.Volume(signingPrivateKeyVolume),
		k8sfactory.Volume(githubSecretVolume),
		k8sfactory.Volume(cookieSecretVolume),
		k8sfactory.Volume(configVolume),
		k8sfactory.Volume(configProxyVolume),
		k8sfactory.Volume(idpSecretVolume),
		k8sfactory.Volume(internalTokenVolume),
		k8sfactory.Volume(datastoreClientCertVolume),
	)
	pod := k8sfactory.PodFactory(nil,
		k8sfactory.LabelMap(r.LabelsForMain()),
		k8sfactory.Annotation(fmt.Sprintf("checksum/%s", configFilename), hex.EncodeToString(confHash[:])),
		k8sfactory.Container(proxyContainer),
		k8sfactory.Volume(caVolume),
		k8sfactory.Volume(serverCertVolume),
		k8sfactory.Volume(signingPrivateKeyVolume),
		k8sfactory.Volume(githubSecretVolume),
		k8sfactory.Volume(cookieSecretVolume),
		k8sfactory.Volume(configVolume),
		k8sfactory.Volume(configProxyVolume),
		k8sfactory.Volume(idpSecretVolume),
		k8sfactory.Volume(internalTokenVolume),
		k8sfactory.Volume(datastoreClientCertVolume),
	)
	if r.Spec.HttpPort != 0 {
		pod = k8sfactory.PodFactory(pod,
			k8sfactory.Port("http", corev1.ProtocolTCP, proxyHttpPort),
		)
	}
	if r.Spec.AntiAffinity {
		pod = k8sfactory.PodFactory(pod,
			k8sfactory.PreferredInterPodAntiAffinity(
				100,
				k8sfactory.MatchLabel(r.LabelsForMain()),
				"kubernetes.io/hostname",
			),
		)
	}
	deployment := k8sfactory.DeploymentFactory(nil,
		k8sfactory.Name(r.DeploymentNameForMain()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.ControlledBy(r.Object, scheme.Scheme),
		k8sfactory.Replicas(r.Spec.Replicas),
		k8sfactory.MatchLabelSelector(r.LabelsForMain()),
		k8sfactory.Pod(pod),
	)

	pdb := k8sfactory.PodDisruptionBudgetFactory(nil,
		k8sfactory.Name(r.PodDisruptionBudgetNameForMain()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.ControlledBy(r.Object, scheme.Scheme),
		k8sfactory.MinAvailable(int(r.Spec.Replicas/2)),
		k8sfactory.MatchLabelSelector(r.LabelsForMain()),
	)

	var port int32 = 443
	if r.Spec.Port != 0 {
		port = r.Spec.Port
	}
	svc := k8sfactory.ServiceFactory(nil,
		k8sfactory.Name(r.ServiceNameForMain()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.ControlledBy(r.Object, scheme.Scheme),
		k8sfactory.LoadBalancer,
		k8sfactory.MatchLabelSelector(r.LabelsForMain()),
		k8sfactory.TargetPort("https", corev1.ProtocolTCP, port, intstr.FromInt(proxyPort)),
		k8sfactory.TrafficPolicyLocal,
	)
	if r.Spec.HttpPort != 0 {
		svc = k8sfactory.ServiceFactory(svc,
			k8sfactory.Port("http", corev1.ProtocolTCP, r.Spec.HttpPort),
		)
	}

	internalApiSvc := k8sfactory.ServiceFactory(nil,
		k8sfactory.Name(r.ServiceNameForInternalApi()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.ControlledBy(r.Object, scheme.Scheme),
		k8sfactory.ClusterIP,
		k8sfactory.MatchLabelSelector(r.LabelsForMain()),
		k8sfactory.Port("http", corev1.ProtocolTCP, internalApiPort),
	)

	reverseProxyConf, err := r.ReverseProxyConfig()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return &process{
		Deployment:          deployment,
		PodDisruptionBudget: pdb,
		Service:             []*corev1.Service{svc, internalApiSvc},
		ConfigMaps:          []*corev1.ConfigMap{conf, reverseProxyConf},
	}, nil
}

func (r *HeimdallrProxy) IdealDashboard() (*process, error) {
	if err := r.checkSelfSignedIssuer(); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	caVolume := k8sfactory.NewSecretVolumeSource(
		"ca-cert",
		caCertMountPath,
		r.CASecret,
		corev1.KeyToPath{Key: caCertificateFilename, Path: caCertificateFilename},
	)
	configVolume := k8sfactory.NewConfigMapVolumeSource("config", configMountPath, r.ConfigNameForDashboard())
	internalTokenVolume := k8sfactory.NewSecretVolumeSource("internal-token", internalTokenMountPath, r.InternalTokenSecret)

	var privateKeyVolume *k8sfactory.VolumeSource
	if r.selfSignedIssuer {
		privateKeyVolume = k8sfactory.NewSecretVolumeSource("privatekey", signPrivateKeyPath, r.SigningPrivateKey)
	}

	conf, err := r.ConfigForDashboard()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	confHash := sha256.Sum256([]byte(conf.Data[configFilename]))

	dashboardContainer := k8sfactory.ContainerFactory(nil,
		k8sfactory.Name("dashboard"),
		k8sfactory.Image(fmt.Sprintf("%s:%s", DashboardImageRepository, r.Version()), []string{dashboardCommand}),
		k8sfactory.Args("-c", fmt.Sprintf("%s/%s", configMountPath, configFilename)),
		k8sfactory.PullPolicy(corev1.PullIfNotPresent),
		k8sfactory.LivenessProbe(k8sfactory.HTTPProbe(dashboardPort, "/liveness")),
		k8sfactory.ReadinessProbe(k8sfactory.HTTPProbe(dashboardPort, "/readiness")),
		k8sfactory.Requests(corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("10m"),
			corev1.ResourceMemory: resource.MustParse("64Mi"),
		}),
		k8sfactory.Limits(corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("256Mi"),
		}),
		k8sfactory.Volume(caVolume),
		k8sfactory.Volume(internalTokenVolume),
		k8sfactory.Volume(configVolume),
		k8sfactory.Volume(privateKeyVolume),
	)
	pod := k8sfactory.PodFactory(nil,
		k8sfactory.LabelMap(r.LabelsForDashboard()),
		k8sfactory.Annotation(fmt.Sprintf("checksum/%s", configFilename), hex.EncodeToString(confHash[:])),
		k8sfactory.Container(dashboardContainer),
		k8sfactory.Volume(caVolume),
		k8sfactory.Volume(internalTokenVolume),
		k8sfactory.Volume(configVolume),
		k8sfactory.Volume(privateKeyVolume),
	)
	if r.Spec.AntiAffinity {
		pod = k8sfactory.PodFactory(pod,
			k8sfactory.PreferredInterPodAntiAffinity(
				100,
				k8sfactory.MatchLabel(r.LabelsForDashboard()),
				"kubernetes.io/hostname",
			),
		)
	}
	replicas := r.Spec.DashboardReplicas
	if replicas == 0 {
		replicas = 3 // This is default value of DashboardReplicas.
	}
	deployment := k8sfactory.DeploymentFactory(nil,
		k8sfactory.Name(r.DeploymentNameForDashboard()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.ControlledBy(r.Object, scheme.Scheme),
		k8sfactory.Replicas(replicas),
		k8sfactory.MatchLabelSelector(r.LabelsForDashboard()),
		k8sfactory.Pod(pod),
	)

	pdb := k8sfactory.PodDisruptionBudgetFactory(nil,
		k8sfactory.Name(r.PodDisruptionBudgetNameForDashboard()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.MatchLabelSelector(r.LabelsForDashboard()),
		k8sfactory.MinAvailable(int(replicas/2)),
	)

	svc := k8sfactory.ServiceFactory(nil,
		k8sfactory.Name(r.ServiceNameForDashboard()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.MatchLabelSelector(r.LabelsForDashboard()),
		k8sfactory.ClusterIP,
		k8sfactory.Port("http", corev1.ProtocolTCP, dashboardPort),
	)

	return &process{
		Deployment:          deployment,
		PodDisruptionBudget: pdb,
		Service:             []*corev1.Service{svc},
		ConfigMaps:          []*corev1.ConfigMap{conf},
	}, nil
}

func (r *HeimdallrProxy) IdealRPCServer() (*process, error) {
	if r.Datastore == nil {
		return nil, controllerbase.WrapRetryError(errors.New("EtcdCluster is not created yet"))
	}

	conf, err := r.ConfigForRPCServer()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	confHash := sha256.Sum256([]byte(conf.Data[configFilename]))

	caVolume := k8sfactory.NewSecretVolumeSource("ca-cert", caCertMountPath, r.CASecret)
	signingPrivateKeyVolume := k8sfactory.NewSecretVolumeSource("signing-priv-key", signPrivateKeyPath, r.SigningPrivateKey)
	configVolume := k8sfactory.NewConfigMapVolumeSource("config", configMountPath, r.ConfigNameForRPCServer())
	configProxyVolume := k8sfactory.NewConfigMapVolumeSource("config-proxy", proxyConfigMountPath, r.ReverseProxyConfigName())
	internalTokenVolume := k8sfactory.NewSecretVolumeSource("internal-token", internalTokenMountPath, r.InternalTokenSecret)
	datastoreClientCertVolume := k8sfactory.NewSecretVolumeSource("datastore-client-cert", datastoreCertMountPath, r.DatastoreClientCertSecret)

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
	rpcServerContainer := k8sfactory.ContainerFactory(nil,
		k8sfactory.Name("rpcserver"),
		k8sfactory.Image(fmt.Sprintf("%s:%s", RPCServerImageRepository, r.Version()), []string{rpcServerCommand}),
		k8sfactory.Args("-c", fmt.Sprintf("%s/%s", configMountPath, configFilename)),
		k8sfactory.LivenessProbe(k8sfactory.ExecProbe(
			"/usr/local/bin/grpc_health_probe",
			fmt.Sprintf("-addr=:%d", rpcServerPort),
			"-tls",
			fmt.Sprintf("-tls-ca-cert=%s/%s", caCertMountPath, caCertificateFilename),
			fmt.Sprintf("-tls-server-name=%s", rpc.ServerHostname),
		)),
		k8sfactory.ReadinessProbe(k8sfactory.ExecProbe(
			"/usr/local/bin/grpc_health_probe",
			fmt.Sprintf("-addr=:%d", rpcServerPort),
			"-tls",
			fmt.Sprintf("-tls-ca-cert=%s/%s", caCertMountPath, caCertificateFilename),
			fmt.Sprintf("-tls-server-name=%s", rpc.ServerHostname),
		)),
		k8sfactory.Port("https", corev1.ProtocolTCP, rpcServerPort),
		k8sfactory.Port("metrics", corev1.ProtocolTCP, rpcMetricsServerPort),
		k8sfactory.Requests(resources.Requests),
		k8sfactory.Limits(resources.Limits),
		k8sfactory.Volume(caVolume),
		k8sfactory.Volume(signingPrivateKeyVolume),
		k8sfactory.Volume(configVolume),
		k8sfactory.Volume(configProxyVolume),
		k8sfactory.Volume(internalTokenVolume),
		k8sfactory.Volume(datastoreClientCertVolume),
	)
	pod := k8sfactory.PodFactory(nil,
		k8sfactory.LabelMap(r.LabelsForRPCServer()),
		k8sfactory.Annotation(fmt.Sprintf("checksum/%s", configFilename), hex.EncodeToString(confHash[:])),
		k8sfactory.Container(rpcServerContainer),
		k8sfactory.Volume(caVolume),
		k8sfactory.Volume(signingPrivateKeyVolume),
		k8sfactory.Volume(configVolume),
		k8sfactory.Volume(configProxyVolume),
		k8sfactory.Volume(internalTokenVolume),
		k8sfactory.Volume(datastoreClientCertVolume),
	)
	if r.Spec.AntiAffinity {
		pod = k8sfactory.PodFactory(pod,
			k8sfactory.PreferredInterPodAntiAffinity(
				100,
				k8sfactory.MatchLabel(r.LabelsForRPCServer()),
				"kubernetes.io/hostname",
			),
		)
	}
	var replicas int32 = 2
	if r.Spec.RPCReplicas > 0 {
		replicas = r.Spec.RPCReplicas
	}
	deployment := k8sfactory.DeploymentFactory(nil,
		k8sfactory.Name(r.DeploymentNameForRPCServer()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.ControlledBy(r.Object, scheme.Scheme),
		k8sfactory.Replicas(replicas),
		k8sfactory.MatchLabelSelector(r.LabelsForRPCServer()),
		k8sfactory.Pod(pod),
	)

	svc := k8sfactory.ServiceFactory(nil,
		k8sfactory.Name(r.ServiceNameForRPCServer()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.ControlledBy(r.Object, scheme.Scheme),
		k8sfactory.LabelMap(r.LabelsForRPCServer()),
		k8sfactory.MatchLabelSelector(r.LabelsForRPCServer()),
		k8sfactory.ClusterIP,
		k8sfactory.Port("h2", corev1.ProtocolTCP, rpcServerPort),
	)

	reverseProxyConf, err := r.ReverseProxyConfig()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	var rpcMetrics *monitoringv1.ServiceMonitor
	if r.Spec.Monitor.PrometheusMonitoring {
		svc.Spec.Ports = append(svc.Spec.Ports, tcpServicePort("metrics", rpcMetricsServerPort, rpcMetricsServerPort))

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

	pdb := k8sfactory.PodDisruptionBudgetFactory(nil,
		k8sfactory.Name(r.PodDisruptionBudgetNameForRPCServer()),
		k8sfactory.Namespace(r.Namespace),
		k8sfactory.ControlledBy(r.Object, scheme.Scheme),
		k8sfactory.MatchLabelSelector(r.LabelsForRPCServer()),
		k8sfactory.MinAvailable(1),
	)

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
	case certmanagerv1alpha2.ClusterIssuerKind:
		ci, err := r.clientset.CertmanagerV1alpha2().ClusterIssuers().Get(context.TODO(), r.Spec.IssuerRef.Name, metav1.GetOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		issuerObj = ci
	case certmanagerv1alpha2.IssuerKind:
		ci, err := r.clientset.CertmanagerV1alpha2().Issuers(r.Namespace).Get(context.TODO(), r.Spec.IssuerRef.Name, metav1.GetOptions{})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		issuerObj = ci
	}

	switch v := issuerObj.(type) {
	case *certmanagerv1alpha2.ClusterIssuer:
		if v.Spec.SelfSigned != nil {
			r.selfSignedIssuer = true
		}
		if v.Spec.CA != nil {
			return errors.New("controllers: ClusterIssuer.Spec.NewCA is not supported")
		}
	case *certmanagerv1alpha2.Issuer:
		if v.Spec.SelfSigned != nil {
			r.selfSignedIssuer = true
		}
		if v.Spec.CA != nil {
			r.selfSignedIssuer = true
		}
	}

	return nil
}

type RoleBindings []*proxyv1alpha2.RoleBinding

func (rb RoleBindings) Select(fn func(*proxyv1alpha2.RoleBinding) bool) []*proxyv1alpha2.RoleBinding {
	n := make([]*proxyv1alpha2.RoleBinding, 0)
	for _, v := range rb {
		if fn(v) {
			n = append(n, v)
		}
	}

	return n
}

func toConfigPermissions(in proxyv1alpha2.BackendSpec) []*configv2.Permission {
	permissions := make([]*configv2.Permission, 0, len(in.Permissions))
	for _, p := range in.Permissions {
		locations := make([]configv2.Location, len(p.Locations))
		for j, u := range p.Locations {
			locations[j] = configv2.Location{
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
		permissions = append(permissions, &configv2.Permission{
			Name:      p.Name,
			Locations: locations,
			WebHook:   p.Webhook,
		})
	}

	return permissions
}

func findService(lister listers.ServiceLister, sel *proxyv1alpha2.ServiceSelector, namespace string) (*corev1.Service, error) {
	ns := sel.Namespace
	if ns == "" {
		ns = namespace
	}
	if sel.Name != "" {
		svc, err := lister.Services(ns).Get(sel.Name)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		return svc, nil
	}

	selector, err := metav1.LabelSelectorAsSelector(&sel.LabelSelector)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	services, err := lister.Services(ns).List(selector)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if len(services) == 0 {
		return nil, xerrors.Errorf("%s not found", sel.LabelSelector.String())
	}
	if len(services) > 1 {
		return nil, xerrors.Errorf("Found %d services: %s", len(services), sel.LabelSelector.String())
	}

	return services[0], nil
}

func tcpServicePort(name string, port, targetPort int) corev1.ServicePort {
	return corev1.ServicePort{
		Name:       name,
		Protocol:   corev1.ProtocolTCP,
		Port:       int32(port),
		TargetPort: intstr.FromInt(targetPort),
	}
}
