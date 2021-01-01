package proxy

import (
	"net/url"
	"reflect"

	"go.uber.org/zap"
	"golang.org/x/xerrors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	proxyv1alpha1 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha1"
	proxyv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha2"
	"go.f110.dev/heimdallr/operator/pkg/webhook"
	"go.f110.dev/heimdallr/pkg/logger"
)

func register(kind string, f webhook.ConvertFunc, b webhook.ConvertFunc) {
	fromGV := proxyv1alpha1.SchemeGroupVersion
	to := proxyv1alpha2.SchemeGroupVersion

	from := fromGV.WithKind(kind)
	webhook.DefaultConverter.Register(&from, &to, f)

	fromGV = proxyv1alpha2.SchemeGroupVersion
	from = fromGV.WithKind(kind)
	to = proxyv1alpha1.SchemeGroupVersion
	webhook.DefaultConverter.Register(&from, &to, b)
}

func init() {
	register("Proxy", V1Alpha1ProxyToV1Alpha2Proxy, V1Alpha2ProxyToV1Alpha1Proxy)
	register("Backend", V1Alpha1BackendToV1Alpha2Backend, V1Alpha2BackendToV1Alpha1Backend)
	register("Role", V1Alpha1RoleToV1Alpha2Role, V1Alpha2RoleToV1Alpha2Role)
	register("RpcPermission", V1Alpha1RpcPermissionToV1Alpha2RpcPermission, V1Alpha2RpcPermissionToV1Alpha1RpcPermission)
	register("RoleBinding", V1Alpha1RoleBindingToV1Alpha2RoleBinding, V1Alpha2RoleBindingToV1Alpha1RoleBinding)
}

func V1Alpha1ProxyToV1Alpha2Proxy(in runtime.Object) (runtime.Object, error) {
	// in is UnstructuredJSONScheme
	un, ok := in.(runtime.Unstructured)
	if !ok {
		logger.Log.Error("in is not Unstructured", zap.String("type_of", reflect.TypeOf(in).String()))
		return nil, xerrors.New("unexpected input data type")
	}

	before := &proxyv1alpha1.Proxy{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.UnstructuredContent(), before)
	if err != nil {
		logger.Log.Warn("Failed convert to the object from unstructured", zap.Error(err))
		return nil, err
	}
	logger.Log.Debug("Covert from v1alpha1.Proxy", zap.String("name", before.Name))

	after := &proxyv1alpha2.Proxy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: proxyv1alpha2.SchemeGroupVersion.String(),
			Kind:       before.Kind,
		},
		ObjectMeta: before.ObjectMeta,
		Spec: proxyv1alpha2.ProxySpec{
			Domain:         before.Spec.Domain,
			Port:           before.Spec.Port,
			HttpPort:       before.Spec.HttpPort,
			Version:        before.Spec.Version,
			LoadBalancerIP: before.Spec.LoadBalancerIP,
			CertificateAuthority: &proxyv1alpha2.CertificateAuthoritySpec{
				Local: &proxyv1alpha2.LocalCertificateAuthoritySpec{
					Name:              before.Name,
					Organization:      before.Spec.Organization,
					AdministratorUnit: before.Spec.AdministratorUnit,
					Country:           before.Spec.Country,
				},
			},
			IssuerRef: before.Spec.IssuerRef,
			IdentityProvider: proxyv1alpha2.IdentityProviderSpec{
				Provider:    before.Spec.IdentityProvider.Provider,
				ClientId:    before.Spec.IdentityProvider.ClientId,
				RedirectUrl: before.Spec.IdentityProvider.RedirectUrl,
				ClientSecretRef: proxyv1alpha2.SecretSelector{
					Name: before.Spec.IdentityProvider.ClientSecretRef.Name,
					Key:  before.Spec.IdentityProvider.ClientSecretRef.Key,
				},
			},
			RootUsers: before.Spec.RootUsers,
			Session: proxyv1alpha2.SessionSpec{
				Type: before.Spec.Session.Type,
				KeySecretRef: proxyv1alpha2.SecretSelector{
					Name: before.Spec.Session.KeySecretRef.Name,
					Key:  before.Spec.Session.KeySecretRef.Key,
				},
			},
			Replicas:          before.Spec.Replicas,
			DashboardReplicas: before.Spec.DashboardReplicas,
			BackendSelector: proxyv1alpha2.LabelSelector{
				LabelSelector: before.Spec.BackendSelector.LabelSelector,
				Namespace:     before.Spec.BackendSelector.Namespace,
			},
			RoleSelector: proxyv1alpha2.LabelSelector{
				LabelSelector: before.Spec.RoleSelector.LabelSelector,
				Namespace:     before.Spec.RoleSelector.Namespace,
			},
			RpcPermissionSelector: proxyv1alpha2.LabelSelector{
				LabelSelector: before.Spec.RpcPermissionSelector.LabelSelector,
				Namespace:     before.Spec.RpcPermissionSelector.Namespace,
			},
			Monitor: proxyv1alpha2.MonitorSpec{
				PrometheusMonitoring: before.Spec.Monitor.PrometheusMonitoring,
				Labels:               before.Spec.Monitor.Labels,
			},
			Backup: proxyv1alpha2.BackupSpec{
				IntervalInSecond: before.Spec.Backup.IntervalInSecond,
				MaxBackups:       before.Spec.Backup.MaxBackups,
				Bucket:           before.Spec.Backup.Bucket,
				Path:             before.Spec.Backup.Path,
				Endpoint:         before.Spec.Backup.Endpoint,
				CredentialRef: proxyv1alpha2.SecretSelector{
					Name: before.Spec.Backup.CredentialRef.Name,
					Key:  before.Spec.Backup.CredentialRef.Key,
				},
			},
			ProxyResources:     before.Spec.ProxyResources,
			RPCServerResources: before.Spec.RPCServerResources,
			Development:        before.Spec.Development,
		},
		Status: proxyv1alpha2.ProxyStatus{
			Ready:                       before.Status.Ready,
			Phase:                       proxyv1alpha2.ProxyPhase(before.Status.Phase),
			NumOfBackends:               before.Status.NumOfBackends,
			NumOfRoles:                  before.Status.NumOfRoles,
			NumOfRpcPermissions:         before.Status.NumOfRpcPermissions,
			CASecretName:                before.Status.CASecretName,
			SigningPrivateKeySecretName: before.Status.SigningPrivateKeySecretName,
			GithubWebhookSecretName:     before.Status.GithubWebhookSecretName,
			CookieSecretName:            before.Status.CookieSecretName,
			InternalTokenSecretName:     before.Status.InternalTokenSecretName,
		},
	}

	if before.Spec.DataStore != nil {
		if before.Spec.DataStore.Etcd != nil {
			after.Spec.DataStore.Etcd = &proxyv1alpha2.ProxyDataStoreEtcdSpec{
				Version: before.Spec.DataStore.Etcd.Version,
				Defragment: proxyv1alpha2.DefragmentSpec{
					Schedule: before.Spec.DataStore.Etcd.Defragment.Schedule,
				},
				AntiAffinity: before.Spec.DataStore.Etcd.AntiAffinity,
			}
		}
	}

	return after, nil
}

func V1Alpha2ProxyToV1Alpha1Proxy(in runtime.Object) (runtime.Object, error) {
	// in is UnstructuredJSONScheme
	un, ok := in.(runtime.Unstructured)
	if !ok {
		logger.Log.Error("in is not Unstructured", zap.String("type_of", reflect.TypeOf(in).String()))
		return nil, xerrors.New("unexpected input data type")
	}

	before := &proxyv1alpha2.Proxy{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.UnstructuredContent(), before)
	if err != nil {
		logger.Log.Warn("Failed convert to the object from unstructured", zap.Error(err))
		return nil, err
	}
	logger.Log.Debug("Covert from v1alpha1.Proxy", zap.String("name", before.Name))

	after := &proxyv1alpha1.Proxy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: proxyv1alpha1.SchemeGroupVersion.String(),
			Kind:       before.Kind,
		},
		ObjectMeta: before.ObjectMeta,
		Spec: proxyv1alpha1.ProxySpec{
			Domain:            before.Spec.Domain,
			Port:              before.Spec.Port,
			HttpPort:          before.Spec.HttpPort,
			Version:           before.Spec.Version,
			LoadBalancerIP:    before.Spec.LoadBalancerIP,
			Country:           before.Spec.CertificateAuthority.Local.Country,
			AdministratorUnit: before.Spec.CertificateAuthority.Local.AdministratorUnit,
			Organization:      before.Spec.CertificateAuthority.Local.Organization,
			Name:              before.Spec.CertificateAuthority.Local.Name,
			IssuerRef:         before.Spec.IssuerRef,
			IdentityProvider: proxyv1alpha1.IdentityProviderSpec{
				Provider:    before.Spec.IdentityProvider.Provider,
				ClientId:    before.Spec.IdentityProvider.ClientId,
				RedirectUrl: before.Spec.IdentityProvider.RedirectUrl,
				ClientSecretRef: proxyv1alpha1.SecretSelector{
					Name: before.Spec.IdentityProvider.ClientSecretRef.Name,
					Key:  before.Spec.IdentityProvider.ClientSecretRef.Key,
				},
			},
			RootUsers: before.Spec.RootUsers,
			Session: proxyv1alpha1.SessionSpec{
				Type: before.Spec.Session.Type,
				KeySecretRef: proxyv1alpha1.SecretSelector{
					Name: before.Spec.Session.KeySecretRef.Name,
					Key:  before.Spec.Session.KeySecretRef.Key,
				},
			},
			Replicas:          before.Spec.Replicas,
			DashboardReplicas: before.Spec.DashboardReplicas,
			BackendSelector: proxyv1alpha1.LabelSelector{
				LabelSelector: before.Spec.BackendSelector.LabelSelector,
				Namespace:     before.Spec.BackendSelector.Namespace,
			},
			RoleSelector: proxyv1alpha1.LabelSelector{
				LabelSelector: before.Spec.RoleSelector.LabelSelector,
				Namespace:     before.Spec.RoleSelector.Namespace,
			},
			RpcPermissionSelector: proxyv1alpha1.LabelSelector{
				LabelSelector: before.Spec.RpcPermissionSelector.LabelSelector,
				Namespace:     before.Spec.RpcPermissionSelector.Namespace,
			},
			Monitor: proxyv1alpha1.MonitorSpec{
				PrometheusMonitoring: before.Spec.Monitor.PrometheusMonitoring,
				Labels:               before.Spec.Monitor.Labels,
			},
			Backup: proxyv1alpha1.BackupSpec{
				IntervalInSecond: before.Spec.Backup.IntervalInSecond,
				MaxBackups:       before.Spec.Backup.MaxBackups,
				Bucket:           before.Spec.Backup.Bucket,
				Path:             before.Spec.Backup.Path,
				Endpoint:         before.Spec.Backup.Endpoint,
				CredentialRef: proxyv1alpha1.SecretSelector{
					Name: before.Spec.Backup.CredentialRef.Name,
					Key:  before.Spec.Backup.CredentialRef.Key,
				},
			},
			ProxyResources:     before.Spec.ProxyResources,
			RPCServerResources: before.Spec.RPCServerResources,
			Development:        before.Spec.Development,
		},
		Status: proxyv1alpha1.ProxyStatus{
			Ready:                       before.Status.Ready,
			Phase:                       proxyv1alpha1.ProxyPhase(before.Status.Phase),
			NumOfBackends:               before.Status.NumOfBackends,
			NumOfRoles:                  before.Status.NumOfRoles,
			NumOfRpcPermissions:         before.Status.NumOfRpcPermissions,
			CASecretName:                before.Status.CASecretName,
			SigningPrivateKeySecretName: before.Status.SigningPrivateKeySecretName,
			GithubWebhookSecretName:     before.Status.GithubWebhookSecretName,
			CookieSecretName:            before.Status.CookieSecretName,
			InternalTokenSecretName:     before.Status.InternalTokenSecretName,
		},
	}

	if before.Spec.DataStore != nil {
		if before.Spec.DataStore.Etcd != nil {
			after.Spec.DataStore = &proxyv1alpha1.ProxyDataStoreSpec{
				Etcd: &proxyv1alpha1.ProxyDataStoreEtcdSpec{
					Version: before.Spec.DataStore.Etcd.Version,
					Defragment: proxyv1alpha1.DefragmentSpec{
						Schedule: before.Spec.DataStore.Etcd.Defragment.Schedule,
					},
					AntiAffinity: before.Spec.DataStore.Etcd.AntiAffinity,
				},
			}
		}
	}

	return after, nil
}

func V1Alpha1BackendToV1Alpha2Backend(in runtime.Object) (runtime.Object, error) {
	// in is UnstructuredJSONScheme
	un, ok := in.(runtime.Unstructured)
	if !ok {
		logger.Log.Error("in is not Unstructured", zap.String("type_of", reflect.TypeOf(in).String()))
		return nil, xerrors.New("unexpected input data type")
	}

	before := &proxyv1alpha1.Backend{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.UnstructuredContent(), before)
	if err != nil {
		logger.Log.Warn("Failed convert to the object from unstructured", zap.Error(err))
		return nil, err
	}
	logger.Log.Debug("Covert v1alpha1.Backend", zap.String("name", before.Name))

	after := &proxyv1alpha2.Backend{
		TypeMeta: metav1.TypeMeta{
			APIVersion: proxyv1alpha2.SchemeGroupVersion.String(),
			Kind:       before.Kind,
		},
		ObjectMeta: before.ObjectMeta,
		Spec: proxyv1alpha2.BackendSpec{
			FQDN:               before.Spec.FQDN,
			Layer:              before.Spec.Layer,
			AllowRootUser:      before.Spec.AllowRootUser,
			DisableAuthn:       before.Spec.DisableAuthn,
			AllowHttp:          before.Spec.AllowHttp,
			MaxSessionDuration: before.Spec.MaxSessionDuration,
		},
		Status: proxyv1alpha2.BackendStatus{},
	}

	socket := false
	if before.Spec.Socket {
		socket = true
	}
	if before.Spec.Upstream != "" {
		u, err := url.Parse(before.Spec.Upstream)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		if u.Scheme == "tcp" {
			socket = true
		}
	}
	if !socket {
		after.Spec.HTTP = []*proxyv1alpha2.BackendHTTPSpec{
			{
				Path: "/",
				ServiceSelector: &proxyv1alpha2.ServiceSelector{
					LabelSelector: before.Spec.ServiceSelector.LabelSelector,
					Namespace:     before.Spec.ServiceSelector.Namespace,
					Name:          before.Spec.ServiceSelector.Name,
					Port:          before.Spec.ServiceSelector.Port,
					Scheme:        before.Spec.ServiceSelector.Scheme,
				},
				Insecure: before.Spec.Insecure,
				Agent:    before.Spec.Agent,
				Upstream: before.Spec.Upstream,
			},
		}
	} else {
		after.Spec.Socket = &proxyv1alpha2.BackendSocketSpec{
			Agent:   before.Spec.Agent,
			Timeout: before.Spec.SocketTimeout,
		}
		if !before.Spec.Agent {
			after.Spec.Socket.Upstream = before.Spec.Upstream
		}
		if before.Spec.ServiceSelector.Port != "" {
			after.Spec.Socket.ServiceSelector = &proxyv1alpha2.ServiceSelector{
				LabelSelector: before.Spec.ServiceSelector.LabelSelector,
				Namespace:     before.Spec.ServiceSelector.Namespace,
				Name:          before.Spec.ServiceSelector.Name,
				Port:          before.Spec.ServiceSelector.Port,
				Scheme:        before.Spec.ServiceSelector.Scheme,
			}
		}
	}

	permissionNames := make(map[string]struct{})
	permissions := make([]proxyv1alpha2.Permission, 0)
	for _, v := range before.Spec.Permissions {
		permissionNames[v.Name] = struct{}{}

		locations := make([]proxyv1alpha2.Location, 0)
		for _, k := range v.Locations {
			locations = append(locations, proxyv1alpha2.Location{
				Any:     k.Any,
				Get:     k.Get,
				Post:    k.Post,
				Put:     k.Put,
				Delete:  k.Delete,
				Head:    k.Head,
				Connect: k.Connect,
				Options: k.Options,
				Trace:   k.Trace,
				Patch:   k.Patch,
			})
		}
		permissions = append(permissions, proxyv1alpha2.Permission{
			Name:      v.Name,
			Locations: locations,
		})
	}
	if before.Spec.Webhook != "" {
		var webhookConf *proxyv1alpha2.WebhookConfiguration
		if before.Spec.WebhookConfiguration != nil {
			webhookConf = &proxyv1alpha2.WebhookConfiguration{
				GitHub: &proxyv1alpha2.GitHubHookConfiguration{
					Repositories:              before.Spec.WebhookConfiguration.Repositories,
					Path:                      before.Spec.WebhookConfiguration.Path,
					Events:                    before.Spec.WebhookConfiguration.Events,
					ContentType:               before.Spec.WebhookConfiguration.ContentType,
					CredentialSecretName:      before.Spec.WebhookConfiguration.CredentialSecretName,
					CredentialSecretNamespace: before.Spec.WebhookConfiguration.CredentialSecretNamespace,
					AppIdKey:                  before.Spec.WebhookConfiguration.AppIdKey,
					InstallationIdKey:         before.Spec.WebhookConfiguration.InstallationIdKey,
					PrivateKeyKey:             before.Spec.WebhookConfiguration.PrivateKeyKey,
				},
			}
		}

		loc := make([]proxyv1alpha2.Location, 0)
		for _, v := range before.Spec.WebhookPath {
			loc = append(loc, proxyv1alpha2.Location{Any: v})
		}

		name := "webhook"
		if _, ok := permissionNames[name]; ok {
			name = "webhook-1"
		}
		permissions = append(permissions, proxyv1alpha2.Permission{
			Name:                 name,
			Webhook:              before.Spec.Webhook,
			WebhookConfiguration: webhookConf,
			Locations:            loc,
		})
	}
	after.Spec.Permissions = permissions

	deployedBy := make([]*proxyv1alpha2.ProxyReference, 0)
	for _, v := range before.Status.DeployedBy {
		deployedBy = append(deployedBy, &proxyv1alpha2.ProxyReference{
			Name:      v.Name,
			Namespace: v.Namespace,
			Url:       v.Url,
		})
	}
	after.Status.DeployedBy = deployedBy

	webhookConfigurations := make([]*proxyv1alpha2.WebhookConfigurationStatus, 0)
	for _, v := range before.Status.WebhookConfigurations {
		webhookConfigurations = append(webhookConfigurations, &proxyv1alpha2.WebhookConfigurationStatus{
			Id:         v.Id,
			Repository: v.Repository,
			UpdateTime: v.UpdateTime,
		})
	}
	after.Status.WebhookConfigurations = webhookConfigurations

	return after, nil
}

func V1Alpha2BackendToV1Alpha1Backend(in runtime.Object) (runtime.Object, error) {
	// in is UnstructuredJSONScheme
	un, ok := in.(runtime.Unstructured)
	if !ok {
		logger.Log.Error("in is not Unstructured", zap.String("type_of", reflect.TypeOf(in).String()))
		return nil, xerrors.New("unexpected input data type")
	}

	before := &proxyv1alpha2.Backend{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.UnstructuredContent(), before)
	if err != nil {
		logger.Log.Warn("Failed convert to the object from unstructured", zap.Error(err))
		return nil, err
	}
	logger.Log.Debug("Covert v1alpha1.Backend", zap.String("name", before.Name))

	after := &proxyv1alpha1.Backend{
		TypeMeta: metav1.TypeMeta{
			APIVersion: proxyv1alpha1.SchemeGroupVersion.String(),
			Kind:       before.Kind,
		},
		ObjectMeta: before.ObjectMeta,
		Spec: proxyv1alpha1.BackendSpec{
			FQDN:               before.Spec.FQDN,
			Layer:              before.Spec.Layer,
			AllowRootUser:      before.Spec.AllowRootUser,
			DisableAuthn:       before.Spec.DisableAuthn,
			AllowHttp:          before.Spec.AllowHttp,
			MaxSessionDuration: before.Spec.MaxSessionDuration,
		},
		Status: proxyv1alpha1.BackendStatus{},
	}

	socket := false
	if before.Spec.Socket != nil {
		socket = true
	}
	if !socket {
		if len(before.Spec.HTTP) > 0 {
			if r := before.Spec.HTTP[0]; r != nil {
				upstream := r.Upstream
				if r.ServiceSelector != nil {
					after.Spec.ServiceSelector = proxyv1alpha1.ServiceSelector{
						LabelSelector: r.ServiceSelector.LabelSelector,
						Namespace:     r.ServiceSelector.Namespace,
						Name:          r.ServiceSelector.Name,
						Port:          r.ServiceSelector.Port,
						Scheme:        r.ServiceSelector.Scheme,
					}
				} else {
					// This is workaround
					upstream = "tcp://127.0.0.1:80"
				}
				after.Spec.Insecure = r.Insecure
				after.Spec.Agent = r.Agent
				after.Spec.Upstream = upstream
			}
		}
	} else {
		after.Spec.Socket = true
		if before.Spec.Socket.ServiceSelector != nil {
			after.Spec.ServiceSelector = proxyv1alpha1.ServiceSelector{
				LabelSelector: before.Spec.Socket.ServiceSelector.LabelSelector,
				Namespace:     before.Spec.Socket.ServiceSelector.Namespace,
				Name:          before.Spec.Socket.ServiceSelector.Name,
				Port:          before.Spec.Socket.ServiceSelector.Port,
				Scheme:        before.Spec.Socket.ServiceSelector.Scheme,
			}
		}
		after.Spec.Upstream = before.Spec.Socket.Upstream
		after.Spec.Agent = before.Spec.Socket.Agent
		after.Spec.SocketTimeout = before.Spec.Socket.Timeout
	}

	permissionNames := make(map[string]struct{})
	permissions := make([]proxyv1alpha1.Permission, 0)
	for _, v := range before.Spec.Permissions {
		permissionNames[v.Name] = struct{}{}

		path := make([]string, 0)
		locations := make([]proxyv1alpha1.Location, 0)
		for _, k := range v.Locations {
			locations = append(locations, proxyv1alpha1.Location{
				Any:     k.Any,
				Get:     k.Get,
				Post:    k.Post,
				Put:     k.Put,
				Delete:  k.Delete,
				Head:    k.Head,
				Connect: k.Connect,
				Options: k.Options,
				Trace:   k.Trace,
				Patch:   k.Patch,
			})
			path = append(path, k.Any)
		}
		permissions = append(permissions, proxyv1alpha1.Permission{
			Name:      v.Name,
			Locations: locations,
		})

		if v.WebhookConfiguration != nil {
			after.Spec.Webhook = v.Webhook
			after.Spec.WebhookPath = path
			after.Spec.WebhookConfiguration = &proxyv1alpha1.WebhookConfiguration{
				GitHubHookConfiguration: proxyv1alpha1.GitHubHookConfiguration{
					Repositories:              v.WebhookConfiguration.GitHub.Repositories,
					Path:                      path[0],
					Events:                    v.WebhookConfiguration.GitHub.Events,
					ContentType:               v.WebhookConfiguration.GitHub.ContentType,
					CredentialSecretName:      v.WebhookConfiguration.GitHub.CredentialSecretName,
					CredentialSecretNamespace: v.WebhookConfiguration.GitHub.CredentialSecretNamespace,
					AppIdKey:                  v.WebhookConfiguration.GitHub.AppIdKey,
					InstallationIdKey:         v.WebhookConfiguration.GitHub.InstallationIdKey,
					PrivateKeyKey:             v.WebhookConfiguration.GitHub.PrivateKeyKey,
				},
			}
		}
	}
	after.Spec.Permissions = permissions

	deployedBy := make([]*proxyv1alpha1.ProxyReference, 0)
	for _, v := range before.Status.DeployedBy {
		deployedBy = append(deployedBy, &proxyv1alpha1.ProxyReference{
			Name:      v.Name,
			Namespace: v.Namespace,
			Url:       v.Url,
		})
	}
	after.Status.DeployedBy = deployedBy

	webhookConfigurations := make([]*proxyv1alpha1.WebhookConfigurationStatus, 0)
	for _, v := range before.Status.WebhookConfigurations {
		webhookConfigurations = append(webhookConfigurations, &proxyv1alpha1.WebhookConfigurationStatus{
			Id:         v.Id,
			Repository: v.Repository,
			UpdateTime: v.UpdateTime,
		})
	}
	after.Status.WebhookConfigurations = webhookConfigurations

	return after, nil
}

func V1Alpha1RoleToV1Alpha2Role(in runtime.Object) (runtime.Object, error) {
	// in is UnstructuredJSONScheme
	un, ok := in.(runtime.Unstructured)
	if !ok {
		logger.Log.Error("in is not Unstructured", zap.String("type_of", reflect.TypeOf(in).String()))
		return nil, xerrors.New("unexpected input data type")
	}

	before := &proxyv1alpha1.Role{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.UnstructuredContent(), before)
	if err != nil {
		logger.Log.Warn("Failed convert to the object from unstructured", zap.Error(err))
		return nil, err
	}

	return &proxyv1alpha2.Role{
		TypeMeta: metav1.TypeMeta{
			APIVersion: proxyv1alpha2.SchemeGroupVersion.String(),
			Kind:       before.Kind,
		},
		ObjectMeta: before.ObjectMeta,
		Spec: proxyv1alpha2.RoleSpec{
			Title:          before.Spec.Title,
			Description:    before.Spec.Description,
			AllowDashboard: before.Spec.AllowDashboard,
		},
	}, nil
}

func V1Alpha2RoleToV1Alpha2Role(in runtime.Object) (runtime.Object, error) {
	// in is UnstructuredJSONScheme
	un, ok := in.(runtime.Unstructured)
	if !ok {
		logger.Log.Error("in is not Unstructured", zap.String("type_of", reflect.TypeOf(in).String()))
		return nil, xerrors.New("unexpected input data type")
	}

	before := &proxyv1alpha2.Role{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.UnstructuredContent(), before)
	if err != nil {
		logger.Log.Warn("Failed convert to the object from unstructured", zap.Error(err))
		return nil, err
	}

	return &proxyv1alpha1.Role{
		TypeMeta: metav1.TypeMeta{
			APIVersion: proxyv1alpha1.SchemeGroupVersion.String(),
			Kind:       before.Kind,
		},
		ObjectMeta: before.ObjectMeta,
		Spec: proxyv1alpha1.RoleSpec{
			Title:          before.Spec.Title,
			Description:    before.Spec.Description,
			AllowDashboard: before.Spec.AllowDashboard,
		},
	}, nil
}

func V1Alpha1RpcPermissionToV1Alpha2RpcPermission(in runtime.Object) (runtime.Object, error) {
	// in is UnstructuredJSONScheme
	un, ok := in.(runtime.Unstructured)
	if !ok {
		logger.Log.Error("in is not Unstructured", zap.String("type_of", reflect.TypeOf(in).String()))
		return nil, xerrors.New("unexpected input data type")
	}

	before := &proxyv1alpha1.RpcPermission{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.UnstructuredContent(), before)
	if err != nil {
		logger.Log.Warn("Failed convert to the object from unstructured", zap.Error(err))
		return nil, err
	}

	return &proxyv1alpha2.RpcPermission{
		TypeMeta: metav1.TypeMeta{
			APIVersion: proxyv1alpha2.SchemeGroupVersion.String(),
			Kind:       before.Kind,
		},
		ObjectMeta: before.ObjectMeta,
		Spec: proxyv1alpha2.RpcPermissionSpec{
			Allow: before.Spec.Allow,
		},
	}, nil
}

func V1Alpha2RpcPermissionToV1Alpha1RpcPermission(in runtime.Object) (runtime.Object, error) {
	// in is UnstructuredJSONScheme
	un, ok := in.(runtime.Unstructured)
	if !ok {
		logger.Log.Error("in is not Unstructured", zap.String("type_of", reflect.TypeOf(in).String()))
		return nil, xerrors.New("unexpected input data type")
	}

	before := &proxyv1alpha2.RpcPermission{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.UnstructuredContent(), before)
	if err != nil {
		logger.Log.Warn("Failed convert to the object from unstructured", zap.Error(err))
		return nil, err
	}

	return &proxyv1alpha1.RpcPermission{
		TypeMeta: metav1.TypeMeta{
			APIVersion: proxyv1alpha1.SchemeGroupVersion.String(),
			Kind:       before.Kind,
		},
		ObjectMeta: before.ObjectMeta,
		Spec: proxyv1alpha1.RpcPermissionSpec{
			Allow: before.Spec.Allow,
		},
	}, nil
}

func V1Alpha1RoleBindingToV1Alpha2RoleBinding(in runtime.Object) (runtime.Object, error) {
	// in is UnstructuredJSONScheme
	un, ok := in.(runtime.Unstructured)
	if !ok {
		logger.Log.Error("in is not Unstructured", zap.String("type_of", reflect.TypeOf(in).String()))
		return nil, xerrors.New("unexpected input data type")
	}

	before := &proxyv1alpha1.RoleBinding{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.UnstructuredContent(), before)
	if err != nil {
		logger.Log.Warn("Failed convert to the object from unstructured", zap.Error(err))
		return nil, err
	}

	subjects := make([]proxyv1alpha2.Subject, 0)
	for _, v := range before.Subjects {
		subjects = append(subjects, proxyv1alpha2.Subject{
			Kind:       v.Kind,
			Name:       v.Name,
			Namespace:  v.Namespace,
			Permission: v.Permission,
		})
	}

	return &proxyv1alpha2.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: proxyv1alpha2.SchemeGroupVersion.String(),
			Kind:       before.Kind,
		},
		ObjectMeta: before.ObjectMeta,
		Subjects:   subjects,
		RoleRef: proxyv1alpha2.RoleRef{
			Name:      before.RoleRef.Name,
			Namespace: before.RoleRef.Namespace,
		},
	}, nil
}

func V1Alpha2RoleBindingToV1Alpha1RoleBinding(in runtime.Object) (runtime.Object, error) {
	// in is UnstructuredJSONScheme
	un, ok := in.(runtime.Unstructured)
	if !ok {
		logger.Log.Error("in is not Unstructured", zap.String("type_of", reflect.TypeOf(in).String()))
		return nil, xerrors.New("unexpected input data type")
	}

	before := &proxyv1alpha2.RoleBinding{}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.UnstructuredContent(), before)
	if err != nil {
		logger.Log.Warn("Failed convert to the object from unstructured", zap.Error(err))
		return nil, err
	}

	subjects := make([]proxyv1alpha1.Subject, 0)
	for _, v := range before.Subjects {
		subjects = append(subjects, proxyv1alpha1.Subject{
			Kind:       v.Kind,
			Name:       v.Name,
			Namespace:  v.Namespace,
			Permission: v.Permission,
		})
	}

	return &proxyv1alpha1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: proxyv1alpha1.SchemeGroupVersion.String(),
			Kind:       before.Kind,
		},
		ObjectMeta: before.ObjectMeta,
		Subjects:   subjects,
		RoleRef: proxyv1alpha1.RoleRef{
			Name:      before.RoleRef.Name,
			Namespace: before.RoleRef.Namespace,
		},
	}, nil
}
