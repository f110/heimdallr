/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	mrand "math/rand"
	"time"

	"github.com/f110/lagrangian-proxy/pkg/auth"
	"github.com/f110/lagrangian-proxy/pkg/config"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/discovery"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	cconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/yaml"

	etcdcluster "github.com/coreos/etcd-operator/pkg/apis/etcd/v1beta2"
	proxyv1 "github.com/f110/lagrangian-proxy/operator/api/v1"
	certmanager "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha2"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	proxyPort                  = 4000
	dashboardPort              = 4100
	configVolumePath           = "/etc/lagrangian-proxy"
	configMountPath            = configVolumePath + "/config"
	serverCertMountPath        = configVolumePath + "/certs"
	caCertMountPath            = configVolumePath + "/ca"
	identityProviderSecretPath = configVolumePath + "/idp"
	sessionSecretPath          = configVolumePath + "/session"
	signPrivateKeyPath         = configVolumePath + "/privkey"
	githubSecretPath           = configVolumePath + "/github_secret"

	privateKeyFilename          = "privkey.pem"
	githubWebhookSecretFilename = "webhook_secret"
	cookieSecretFilename        = "cookie_secret"
	serverCertificateFilename   = "tls.crt"
	serverPrivateKeyFilename    = "tls.key"
	caCertificateFilename       = "ca.crt"
	caPrivateKeyFilename        = "ca.key"

	letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// LagrangianProxyReconciler reconciles a LagrangianProxy object
type LagrangianProxyReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=proxy.f110.dev,resources=lagrangianproxies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=proxy.f110.dev,resources=lagrangianproxies/status,verbs=get;update;patch

func (r *LagrangianProxyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := r.checkOperator(); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&proxyv1.LagrangianProxy{}).
		Complete(r)
}

func (r *LagrangianProxyReconciler) checkOperator() error {
	cfg, err := cconfig.GetConfig()
	if err != nil {
		return err
	}
	dc := discovery.NewDiscoveryClientForConfigOrDie(cfg)
	_, apiList, err := dc.ServerGroupsAndResources()
	if err != nil {
		return err
	}

	if err := r.existCustomResource(apiList, "etcd.database.coreos.com/v1beta2", "EtcdCluster"); err != nil {
		return err
	}
	if err := r.existCustomResource(apiList, "cert-manager.io/v1alpha2", "Certificate"); err != nil {
		return err
	}

	return nil
}

func (r *LagrangianProxyReconciler) existCustomResource(apiList []*metav1.APIResourceList, groupVersion, kind string) error {
	for _, v := range apiList {
		if v.GroupVersion == groupVersion {
			for _, v := range v.APIResources {
				if v.Kind == kind {
					return nil
				}
			}
		}
	}

	return fmt.Errorf("controllers: %s/%s not found", groupVersion, kind)
}

func (r *LagrangianProxyReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	_ = r.Log.WithValues("lagrangianproxy", req.NamespacedName)

	def := &proxyv1.LagrangianProxy{}
	if err := r.Get(context.Background(), req.NamespacedName, def); err != nil {
		return ctrl.Result{}, err
	}

	if requeue, err := r.preSetup(def, req); err != nil {
		return ctrl.Result{Requeue: requeue, RequeueAfter: 30 * time.Second}, nil
	}

	if err := r.ReconcileConfig(def, req); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.ReconcileDashboardProcess(def, req); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.ReconcileMainProcess(def, req); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *LagrangianProxyReconciler) ReconcileMainProcess(def *proxyv1.LagrangianProxy, req ctrl.Request) error {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: req.Namespace,
		},
	}

	_, err := ctrl.CreateOrUpdate(context.Background(), r, deployment, func() error {
		deployment.Spec = appsv1.DeploymentSpec{
			Replicas: &def.Spec.Replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "lagrangian-proxy", "instance": req.Name, "role": "proxy"},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": "lagrangian-proxy", "instance": req.Name, "role": "proxy"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    "proxy",
							Image:   "quay.io/f110/lagrangian-proxy:latest",
							Command: []string{"/usr/local/bin/lagrangian-proxy"},
							Args:    []string{"-c", fmt.Sprintf("%s/config.yaml", configMountPath)},
							ReadinessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Scheme: corev1.URISchemeHTTPS,
										Path:   "/liveness", // TODO: use readiness proebe
										Port:   intstr.FromInt(proxyPort),
										HTTPHeaders: []corev1.HTTPHeader{
											{Name: "Host", Value: def.Spec.Domain},
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
											{Name: "Host", Value: def.Spec.Domain},
										},
									},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "server-cert",
									MountPath: serverCertMountPath,
								},
								{
									Name:      "ca-cert",
									MountPath: caCertMountPath,
								},
								{
									Name:      "privatekey",
									MountPath: signPrivateKeyPath,
								},
								{
									Name:      "github-secret",
									MountPath: githubSecretPath,
								},
								{
									Name:      "cookie-secret",
									MountPath: sessionSecretPath,
								},
								{
									Name:      "config",
									MountPath: configMountPath,
								},
								{
									Name:      "idp-secret",
									MountPath: identityProviderSecretPath,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "server-cert",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: req.Name + "-cert",
								},
							},
						},
						{
							Name: "ca-cert",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: req.Name + "-ca",
								},
							},
						},
						{
							Name: "privatekey",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: req.Name + "-privkey",
								},
							},
						},
						{
							Name: "github-secret",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: req.Name + "-github-secret",
								},
							},
						},
						{
							Name: "cookie-secret",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: req.Name + "-cookie-secret",
								},
							},
						},
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: req.Name,
									},
								},
							},
						},
						{
							Name: "idp-secret",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: def.Spec.IdentityProvider.ClientSecretRef.Name,
								},
							},
						},
					},
				},
			},
		}
		return ctrl.SetControllerReference(def, deployment, r.Scheme)
	})
	if err != nil {
		return err
	}

	pdb := &policyv1beta1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: req.Namespace,
		},
	}
	minAvailable := intstr.FromInt(int(def.Spec.Replicas / 2))
	_, err = ctrl.CreateOrUpdate(context.Background(), r, pdb, func() error {
		pdb.Spec.Selector = &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "lagrangian-proxy", "instance": req.Name, "role": "proxy"},
		}
		pdb.Spec.MinAvailable = &minAvailable

		return nil
	})
	if err != nil {
		return err
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: req.Namespace,
		},
	}
	var port int32 = 443
	if def.Spec.Port != 0 {
		port = def.Spec.Port
	}
	_, err = ctrl.CreateOrUpdate(context.Background(), r, svc, func() error {
		svc.Spec.Selector = map[string]string{"app": "lagrangian-proxy", "instance": req.Name, "role": "proxy"}
		svc.Spec.Ports = []corev1.ServicePort{
			{
				Name:       "https",
				Port:       port,
				TargetPort: intstr.FromInt(proxyPort),
			},
		}
		svc.Spec.Type = corev1.ServiceTypeLoadBalancer
		svc.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyTypeLocal

		return nil
	})

	return err
}

func (r *LagrangianProxyReconciler) ReconcileDashboardProcess(def *proxyv1.LagrangianProxy, req ctrl.Request) error {
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name + "-dashboard",
			Namespace: req.Namespace,
		},
	}

	var replicas int32 = 3
	_, err := ctrl.CreateOrUpdate(context.Background(), r, deployment, func() error {
		deployment.Spec = appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "lagrangian-proxy", "instance": req.Name, "role": "dashboard"},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": "lagrangian-proxy", "instance": req.Name, "role": "dashboard"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    "proxy",
							Image:   "quay.io/f110/lagrangian-proxy:latest",
							Command: []string{"/usr/local/bin/lagrangian-proxy"},
							Args:    []string{"-c", fmt.Sprintf("%s/config.yaml", configMountPath)},
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
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "ca-cert",
									MountPath: caCertMountPath,
								},
								{
									Name:      "config",
									MountPath: configMountPath,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "ca-cert",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: req.Name + "-ca",
								},
							},
						},
						{
							Name: "config",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: req.Name + "-dashboard",
									},
								},
							},
						},
					},
				},
			},
		}
		return ctrl.SetControllerReference(def, deployment, r.Scheme)
	})
	if err != nil {
		return err
	}

	pdb := &policyv1beta1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name + "-dashboard",
			Namespace: req.Namespace,
		},
	}
	minAvailable := intstr.FromInt(int(def.Spec.Replicas / 2))
	_, err = ctrl.CreateOrUpdate(context.Background(), r, pdb, func() error {
		pdb.Spec.Selector = &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "lagrangian-proxy", "instance": req.Name, "role": "dashboard"},
		}
		pdb.Spec.MinAvailable = &minAvailable

		return nil
	})
	if err != nil {
		return err
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name + "-dashboard",
			Namespace: req.Namespace,
		},
	}
	_, err = ctrl.CreateOrUpdate(context.Background(), r, svc, func() error {
		svc.Spec.Selector = map[string]string{"app": "lagrangian-proxy", "instance": req.Name, "role": "dashboard"}
		svc.Spec.Ports = []corev1.ServicePort{
			{
				Name:       "http",
				Port:       dashboardPort,
				TargetPort: intstr.FromInt(dashboardPort),
			},
		}
		svc.Spec.Type = corev1.ServiceTypeClusterIP

		return nil
	})

	return err
}

func (r *LagrangianProxyReconciler) preSetup(def *proxyv1.LagrangianProxy, req ctrl.Request) (bool, error) {
	requeue := false
	if err := r.ReconcileCertificate(def, req); err != nil {
		r.Log.Error(err, "Reconcile Certificate")
		requeue = true
	}

	if err := r.ReconcileEtcdCluster(def, req); err != nil {
		r.Log.Error(err, "Reconcile DataStore")
		requeue = true
	}

	if requeue {
		return requeue, errors.New("controllers: pre setup is not completed")
	}

	return requeue, nil
}

func (r *LagrangianProxyReconciler) ReconcileCertificate(def *proxyv1.LagrangianProxy, req ctrl.Request) error {
	name := req.Name + "-cert"
	cert := &certmanager.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: req.Namespace},
	}

	_, err := ctrl.CreateOrUpdate(context.Background(), r, cert, func() error {
		cert.Spec.SecretName = name
		cert.Spec.IssuerRef = def.Spec.IssuerRef
		cert.Spec.CommonName = def.Spec.Domain
		cert.Spec.DNSNames = []string{def.Spec.Domain}

		return ctrl.SetControllerReference(def, cert, r.Scheme)
	})
	if err != nil {
		return err
	}

	key, err := client.ObjectKeyFromObject(cert)
	if err != nil {
		return err
	}
	if err := r.Get(context.Background(), key, cert); err != nil {
		return err
	}
	for _, v := range cert.Status.Conditions {
		if v.Status == cmmeta.ConditionTrue {
			return nil
		}
	}

	return errors.New("controllers: certificate is not ready yet")
}

func (r *LagrangianProxyReconciler) ReconcileEtcdCluster(def *proxyv1.LagrangianProxy, req ctrl.Request) error {
	name := req.Name + "-datastore"
	cluster := &etcdcluster.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: req.Namespace},
	}
	_, err := ctrl.CreateOrUpdate(context.Background(), r, cluster, func() error {
		cluster.Spec.Size = 3
		cluster.Spec.Version = "3.3.18"

		return ctrl.SetControllerReference(def, cluster, r.Scheme)
	})
	if err != nil {
		return err
	}

	key, err := client.ObjectKeyFromObject(cluster)
	if err != nil {
		return err
	}
	if err := r.Get(context.Background(), key, cluster); err != nil {
		return err
	}

	for _, v := range cluster.Status.Conditions {
		if v.Status == corev1.ConditionTrue {
			return nil
		}
	}

	return errors.New("controllers: etcd cluster is not ready yet")
}

func (r *LagrangianProxyReconciler) ReconcileConfig(def *proxyv1.LagrangianProxy, req ctrl.Request) error {
	if err := r.generateCACert(def, req); err != nil {
		return err
	}
	if err := r.generatePrivateKey(def, req); err != nil {
		return err
	}
	if err := r.generateGithubSecret(def, req); err != nil {
		return err
	}
	if err := r.generateCookieSecret(def, req); err != nil {
		return err
	}
	if err := r.generateConfig(def, req); err != nil {
		return err
	}

	return nil
}

func (r *LagrangianProxyReconciler) generateCACert(def *proxyv1.LagrangianProxy, req ctrl.Request) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name + "-ca",
			Namespace: req.Namespace,
		},
		Data: make(map[string][]byte),
	}

	return r.createOnce(secret, func() error {
		caName := "Lagrangian Proxy CA"
		if def.Spec.Name != "" {
			caName = def.Spec.Name
		}
		country := "jp"
		if def.Spec.Country != "" {
			country = def.Spec.Country
		}
		cert, privateKey, err := auth.CreateCertificateAuthority(caName, def.Spec.Organization, def.Spec.AdministratorUnit, country)
		if err != nil {
			return err
		}

		b, err := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
		if err != nil {
			return err
		}

		buf := new(bytes.Buffer)
		if err := pem.Encode(buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
			return err
		}
		secret.Data["ca.key"] = buf.Bytes()

		buf = new(bytes.Buffer)
		if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			return err
		}
		secret.Data["ca.crt"] = buf.Bytes()

		return ctrl.SetControllerReference(def, secret, r.Scheme)
	})
}

func (r *LagrangianProxyReconciler) generatePrivateKey(def *proxyv1.LagrangianProxy, req ctrl.Request) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name + "-privkey",
			Namespace: req.Namespace,
		},
		Data: make(map[string][]byte),
	}

	return r.createOnce(secret, func() error {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		b, err := x509.MarshalECPrivateKey(privateKey)
		if err != nil {
			return err
		}
		buf := new(bytes.Buffer)
		if err := pem.Encode(buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
			return err
		}

		secret.Data[privateKeyFilename] = buf.Bytes()
		return ctrl.SetControllerReference(def, secret, r.Scheme)
	})
}

func (r *LagrangianProxyReconciler) generateGithubSecret(def *proxyv1.LagrangianProxy, req ctrl.Request) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name + "-github-secret",
			Namespace: req.Namespace,
		},
		Data: make(map[string][]byte),
	}

	return r.createOnce(secret, func() error {
		b := make([]byte, 32)
		for i := range b {
			b[i] = letters[mrand.Intn(len(letters))]
		}
		secret.Data[githubWebhookSecretFilename] = b

		return ctrl.SetControllerReference(def, secret, r.Scheme)
	})
}

func (r *LagrangianProxyReconciler) generateCookieSecret(def *proxyv1.LagrangianProxy, req ctrl.Request) error {
	if def.Spec.Session.Type != config.SessionTypeSecureCookie {
		return nil
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name + "-cookie-secret",
			Namespace: req.Namespace,
		},
		Data: make(map[string][]byte),
	}

	return r.createOnce(secret, func() error {
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

		return ctrl.SetControllerReference(def, secret, r.Scheme)
	})
}

func (r *LagrangianProxyReconciler) generateConfig(def *proxyv1.LagrangianProxy, req ctrl.Request) error {
	if err := r.generateMainConfig(def, req); err != nil {
		return err
	}
	if err := r.generateDashboardConfig(def, req); err != nil {
		return err
	}

	return nil
}

func (r *LagrangianProxyReconciler) generateMainConfig(def *proxyv1.LagrangianProxy, req ctrl.Request) error {
	conf := &config.Config{
		General: &config.General{
			Enable:     true,
			Bind:       fmt.Sprintf(":%d", proxyPort),
			ServerName: def.Spec.Domain,
			RootUsers:  def.Spec.RootUsers,
			CertFile:   fmt.Sprintf("%s/%s", serverCertMountPath, serverCertificateFilename),
			KeyFile:    fmt.Sprintf("%s/%s", serverCertMountPath, serverPrivateKeyFilename),
			RoleFile:   "./roles.yaml",
			ProxyFile:  "./proxies.yaml",
			CertificateAuthority: &config.CertificateAuthority{
				CertFile:         fmt.Sprintf("%s/%s", caCertMountPath, caCertificateFilename),
				KeyFile:          fmt.Sprintf("%s/%s", caCertMountPath, caPrivateKeyFilename),
				Organization:     def.Spec.Organization,
				OrganizationUnit: def.Spec.AdministratorUnit,
				Country:          def.Spec.Country,
			},
		},
		IdentityProvider: &config.IdentityProvider{
			Provider:         def.Spec.IdentityProvider.Provider,
			ClientId:         def.Spec.IdentityProvider.ClientId,
			ClientSecretFile: fmt.Sprintf("%s/%s", identityProviderSecretPath, def.Spec.IdentityProvider.ClientSecretRef.Key),
			ExtraScopes:      []string{"email"},
			RedirectUrl:      def.Spec.IdentityProvider.RedirectUrl,
		},
		Datastore: &config.Datastore{
			RawUrl:    fmt.Sprintf("etcd://%s:2379", def.Name+"-datastore-client"),
			Namespace: "/lagrangian-proxy/",
		},
		FrontendProxy: &config.FrontendProxy{
			AccessLogFile:           "/tmp/access.log",
			SigningSecretKeyFile:    fmt.Sprintf("%s/%s", signPrivateKeyPath, privateKeyFilename),
			GithubWebHookSecretFile: fmt.Sprintf("%s/%s", githubSecretPath, githubWebhookSecretFilename),
			ExpectCT:                true,
			Session: &config.Session{
				Type:    def.Spec.Session.Type,
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
		return err
	}

	roles := make([]*config.Role, 0)
	roles = append(roles, &config.Role{
		Name:        "admin",
		Title:       "administrator",
		Description: "Proxy administrator a.k.a GOD",
		Bindings: []config.Binding{
			{
				Backend:    "dashboard." + def.Spec.Domain,
				Permission: "all",
			},
		},
	})
	roleBinary, err := yaml.Marshal(roles)
	if err != nil {
		return err
	}

	proxies := make([]*config.Backend, 0)
	proxies = append(proxies, &config.Backend{
		Name:            "dashboard." + def.Spec.Domain,
		Upstream:        "http://localhost:4100",
		AllowAsRootUser: true,
		Permissions: []*config.Permission{
			{
				Name: "all",
				Locations: []config.Location{
					{Any: "/"},
				},
			},
		},
	})
	proxyBinary, err := yaml.Marshal(proxies)
	if err != nil {
		return err
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: req.Namespace,
		},
		Data: make(map[string]string),
	}
	_, err = ctrl.CreateOrUpdate(context.Background(), r, configMap, func() error {
		configMap.Data["config.yaml"] = string(b)
		configMap.Data["roles.yaml"] = string(roleBinary)
		configMap.Data["proxies.yaml"] = string(proxyBinary)

		return ctrl.SetControllerReference(def, configMap, r.Scheme)
	})
	if err != nil {
		return err
	}

	return nil
}

func (r *LagrangianProxyReconciler) generateDashboardConfig(def *proxyv1.LagrangianProxy, req ctrl.Request) error {
	conf := &config.Config{
		General: &config.General{
			Enable: false,
			CertificateAuthority: &config.CertificateAuthority{
				CertFile:         fmt.Sprintf("%s/%s", caCertMountPath, caCertificateFilename),
				KeyFile:          fmt.Sprintf("%s/%s", caCertMountPath, caPrivateKeyFilename),
				Organization:     def.Spec.Organization,
				OrganizationUnit: def.Spec.AdministratorUnit,
				Country:          def.Spec.Country,
			},
		},
		Datastore: &config.Datastore{
			RawUrl:    fmt.Sprintf("etcd://%s:2379", def.Name+"-datastore-client"),
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
		return err
	}

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name + "-dashboard",
			Namespace: req.Namespace,
		},
		Data: make(map[string]string),
	}
	_, err = ctrl.CreateOrUpdate(context.Background(), r, configMap, func() error {
		configMap.Data["config.yaml"] = string(b)

		return ctrl.SetControllerReference(def, configMap, r.Scheme)
	})
	if err != nil {
		return err
	}

	return nil
}

type initFn func() error

func (r *LagrangianProxyReconciler) createOnce(obj runtime.Object, fn initFn) error {
	key, err := client.ObjectKeyFromObject(obj)
	if err != nil {
		return err
	}
	err = r.Get(context.Background(), key, obj)
	if apierrors.IsNotFound(err) {
		if err := fn(); err != nil {
			return err
		}

		return r.Create(context.Background(), obj)
	}

	return nil
}
