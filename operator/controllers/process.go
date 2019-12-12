package controllers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	mrand "math/rand"
	"sort"
	"sync"

	"github.com/f110/lagrangian-proxy/pkg/auth"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/netutil"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	etcdcluster "github.com/coreos/etcd-operator/pkg/apis/etcd/v1beta2"
	proxyv1 "github.com/f110/lagrangian-proxy/operator/api/v1"
	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	EtcdVersion = "3.3.18"

	imageRepository            = "quay.io/f110/lagrangian-proxy"
	defaultImageTag            = "latest"
	defaultCommand             = "/usr/local/bin/lagrangian-proxy"
	proxyPort                  = 4000
	dashboardPort              = 4100
	configVolumePath           = "/etc/lagrangian-proxy"
	configMountPath            = configVolumePath + "/config"
	proxyConfigMountPath       = configVolumePath + "/proxy"
	serverCertMountPath        = configVolumePath + "/certs"
	caCertMountPath            = configVolumePath + "/ca"
	identityProviderSecretPath = configVolumePath + "/idp"
	sessionSecretPath          = configVolumePath + "/session"
	signPrivateKeyPath         = configVolumePath + "/privkey"
	githubSecretPath           = configVolumePath + "/github_secret"

	configFilename              = "config.yaml"
	privateKeyFilename          = "privkey.pem"
	githubWebhookSecretFilename = "webhook_secret"
	cookieSecretFilename        = "cookie_secret"
	serverCertificateFilename   = "tls.crt"
	serverPrivateKeyFilename    = "tls.key"
	caCertificateFilename       = "ca.crt"
	caPrivateKeyFilename        = "ca.key"
	proxyFilename               = "proxies.yaml"
	roleFilename                = "roles.yaml"

	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

type process struct {
	Deployment          *appsv1.Deployment
	PodDisruptionBudget *policyv1beta1.PodDisruptionBudget
	Service             *corev1.Service
	ConfigMaps          []*corev1.ConfigMap
	Secrets             []*corev1.Secret
	Certificate         *certmanager.Certificate
}

type LagrangianProxy struct {
	sync.Mutex

	Name      string
	Namespace string
	Object    *proxyv1.Proxy
	Spec      proxyv1.ProxySpec
	Client    client.Client
}

func NewLagrangianProxy(spec *proxyv1.Proxy, client client.Client) *LagrangianProxy {
	return &LagrangianProxy{
		Name:      spec.Name,
		Namespace: spec.Namespace,
		Client:    client,
		Object:    spec,
		Spec:      spec.Spec,
	}
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

func (r *LagrangianProxy) PodDisruptionBudgetNameForDashboard() string {
	return r.Name + "-dashboard"
}

func (r *LagrangianProxy) ServiceNameForDashboard() string {
	return r.Name + "-dashboard"
}

func (r *LagrangianProxy) ReverseProxyConfigName() string {
	return r.Name + "-proxy"
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

	return backends.Items, nil
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

	return roleList.Items, nil
}

func (r *LagrangianProxy) Certificate() (*certmanager.Certificate, error) {
	backends, err := r.Backends()
	if err != nil {
		return nil, err
	}
	layers := make(map[string]struct{})
	for _, v := range backends {
		if _, ok := layers[v.Spec.Layer]; !ok {
			layers[v.Spec.Layer] = struct{}{}
		}
	}

	domains := []string{r.Spec.Domain, fmt.Sprintf("*.%s", r.Spec.Domain)}
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

func (r *LagrangianProxy) EtcdCluster() *etcdcluster.EtcdCluster {
	cluster := &etcdcluster.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{Name: r.EtcdClusterName(), Namespace: r.Namespace},
		Spec: etcdcluster.ClusterSpec{
			Size:    3,
			Version: EtcdVersion,
		},
	}

	return cluster
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
		cert, privateKey, err := auth.CreateCertificateAuthority(caName, r.Spec.Organization, r.Spec.AdministratorUnit, country)
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

func (r *LagrangianProxy) ConfigForMain() (*corev1.ConfigMap, error) {
	conf := &config.Config{
		General: &config.General{
			Enable:     true,
			Bind:       fmt.Sprintf(":%d", proxyPort),
			ServerName: r.Spec.Domain,
			RootUsers:  r.Spec.RootUsers,
			CertFile:   fmt.Sprintf("%s/%s", serverCertMountPath, serverCertificateFilename),
			KeyFile:    fmt.Sprintf("%s/%s", serverCertMountPath, serverPrivateKeyFilename),
			RoleFile:   fmt.Sprintf("%s/%s", proxyConfigMountPath, roleFilename),
			ProxyFile:  fmt.Sprintf("%s/%s", proxyConfigMountPath, proxyFilename),
			CertificateAuthority: &config.CertificateAuthority{
				CertFile:         fmt.Sprintf("%s/%s", caCertMountPath, caCertificateFilename),
				KeyFile:          fmt.Sprintf("%s/%s", caCertMountPath, caPrivateKeyFilename),
				Organization:     r.Spec.Organization,
				OrganizationUnit: r.Spec.AdministratorUnit,
				Country:          r.Spec.Country,
			},
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
			AccessLogFile:           "/tmp/access.log",
			SigningSecretKeyFile:    fmt.Sprintf("%s/%s", signPrivateKeyPath, privateKeyFilename),
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
			Enable: false,
			CertificateAuthority: &config.CertificateAuthority{
				CertFile:         fmt.Sprintf("%s/%s", caCertMountPath, caCertificateFilename),
				KeyFile:          fmt.Sprintf("%s/%s", caCertMountPath, caPrivateKeyFilename),
				Organization:     r.Spec.Organization,
				OrganizationUnit: r.Spec.AdministratorUnit,
				Country:          r.Spec.Country,
			},
		},
		Datastore: &config.Datastore{
			RawUrl:    fmt.Sprintf("etcd://%s:2379", r.EtcdHost()),
			Namespace: "/lagrangian-proxy/",
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

func (r *LagrangianProxy) LabelsForMain() map[string]string {
	return map[string]string{"app": "lagrangian-proxy", "instance": r.Name, "role": "proxy"}
}

func (r *LagrangianProxy) LabelsForDashboard() map[string]string {
	return map[string]string{"app": "lagrangian-proxy", "instance": r.Name, "role": "dashboard"}
}

func (r *LagrangianProxy) ReverseProxyConfig() (*corev1.ConfigMap, error) {
	backends, err := r.Backends()
	if err != nil {
		return nil, err
	}

	proxies := make([]*config.Backend, len(backends))
	backendMap := make(map[string]*proxyv1.Backend)
	for i, v := range backends {
		backendMap[v.Namespace+"/"+v.Name] = &v

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
		proxies[i] = &config.Backend{
			Name:            v.Name + "." + v.Spec.Layer + "." + r.Spec.Domain,
			Upstream:        v.Spec.Upstream,
			Permissions:     permissions,
			WebHook:         v.Spec.Webhook,
			WebHookPath:     v.Spec.WebhookPath,
			Agent:           v.Spec.Agent,
			AllowAsRootUser: v.Spec.AllowRootUser,
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
		bindings := make([]config.Binding, len(v.Spec.Bindings))
		for k, b := range v.Spec.Bindings {
			namespace := v.Namespace
			if b.Namespace != "" {
				namespace = b.Namespace
			}
			backendHost := ""
			if bn, ok := backendMap[namespace+"/"+b.Name]; ok {
				backendHost = bn.Name + "." + bn.Spec.Layer + "." + r.Spec.Domain
			} else {
				return nil, fmt.Errorf("controller: %s not found", b.Name)
			}

			bindings[k] = config.Binding{
				Permission: b.Permission,
				Backend:    backendHost,
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

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.ReverseProxyConfigName(),
			Namespace: r.Namespace,
		},
		Data: make(map[string]string),
	}
	configMap.Data[roleFilename] = string(roleBinary)
	configMap.Data[proxyFilename] = string(proxyBinary)

	return configMap, nil
}

func (r *LagrangianProxy) MainProcess() (*process, error) {
	secret := &corev1.Secret{}
	err := r.Client.Get(context.Background(), client.ObjectKey{Name: r.Spec.IdentityProvider.ClientSecretRef.Name, Namespace: r.Namespace}, secret)
	if err != nil && apierrors.IsNotFound(err) {
		return nil, err
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
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    "proxy",
							Image:   fmt.Sprintf("%s:%s", imageRepository, defaultImageTag),
							Command: []string{defaultCommand},
							Args:    []string{"-c", fmt.Sprintf("%s/%s", configMountPath, configFilename)},
							ReadinessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Scheme: corev1.URISchemeHTTPS,
										Path:   "/liveness", // TODO: use readiness proebe
										Port:   intstr.FromInt(proxyPort),
										HTTPHeaders: []corev1.HTTPHeader{
											{Name: "Host", Value: r.Spec.Domain},
										},
									},
								},
							},
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Scheme: corev1.URISchemeHTTPS,
										Path:   "/liveness",
										Port:   intstr.FromInt(proxyPort),
										HTTPHeaders: []corev1.HTTPHeader{
											{Name: "Host", Value: r.Spec.Domain},
										},
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
									corev1.ResourceCPU:    resource.MustParse("300m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("1"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "server-cert", MountPath: serverCertMountPath},
								{Name: "ca-cert", MountPath: caCertMountPath},
								{Name: "privatekey", MountPath: signPrivateKeyPath},
								{Name: "github-secret", MountPath: githubSecretPath},
								{Name: "cookie-secret", MountPath: sessionSecretPath},
								{Name: "config", MountPath: configMountPath},
								{Name: "config-proxy", MountPath: proxyConfigMountPath},
								{Name: "idp-secret", MountPath: identityProviderSecretPath},
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

	conf, err := r.ConfigForMain()
	if err != nil {
		return nil, err
	}
	reverseProxyConf, err := r.ReverseProxyConfig()
	if err != nil {
		return nil, err
	}

	caSecert, err := r.CASecret()
	if err != nil {
		return nil, err
	}
	privateKey, err := r.PrivateKeyForSign()
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

	cert, err := r.Certificate()
	if err != nil {
		return nil, err
	}

	return &process{
		Deployment:          deployment,
		PodDisruptionBudget: pdb,
		Service:             svc,
		ConfigMaps:          []*corev1.ConfigMap{conf, reverseProxyConf},
		Secrets: []*corev1.Secret{
			caSecert, privateKey, githubSecret,
			cookieSecret,
		},
		Certificate: cert,
	}, nil
}

func (r *LagrangianProxy) Dashboard() (*process, error) {
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
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    "proxy",
							Image:   fmt.Sprintf("%s:%s", imageRepository, defaultImageTag),
							Command: []string{defaultCommand},
							Args:    []string{"-c", fmt.Sprintf("%s/%s", configMountPath, configFilename)},
							ReadinessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/", // TODO: use readiness probe
										Port: intstr.FromInt(dashboardPort),
									},
								},
							},
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/",
										Port: intstr.FromInt(dashboardPort),
									},
								},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("300m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("1"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "ca-cert", MountPath: caCertMountPath},
								{Name: "config", MountPath: configMountPath},
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
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: r.ConfigNameForDashboard(),
									},
								},
							},
						},
					},
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

	conf, err := r.ConfigForDashboard()
	if err != nil {
		return nil, err
	}

	return &process{
		Deployment:          deployment,
		PodDisruptionBudget: pdb,
		Service:             svc,
		Secrets:             []*corev1.Secret{caSecret},
		ConfigMaps:          []*corev1.ConfigMap{conf},
	}, nil
}
