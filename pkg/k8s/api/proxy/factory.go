package proxy

import (
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/k8s/api/proxyv1alpha2"
	"go.f110.dev/heimdallr/pkg/k8s/client/versioned/scheme"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
)

func Factory(base *proxyv1alpha2.Proxy, traits ...k8sfactory.Trait) *proxyv1alpha2.Proxy {
	var p *proxyv1alpha2.Proxy
	if base == nil {
		p = &proxyv1alpha2.Proxy{}
	} else {
		p = base.DeepCopy()
	}
	if p.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(p)
		if err == nil && !unversioned && len(gvks) > 0 {
			p.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, trait := range traits {
		trait(p)
	}

	return p
}

func Phase(v proxyv1alpha2.ProxyPhase) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Proxy)
		if !ok {
			return
		}
		p.Status.Phase = v
	}
}

func IdentityProvider(provider, clientId, secretName, key string) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Proxy)
		if !ok {
			return
		}
		p.Spec.IdentityProvider.Provider = provider
		p.Spec.IdentityProvider.ClientId = clientId
		p.Spec.IdentityProvider.ClientSecretRef = &proxyv1alpha2.SecretSelector{
			Name: secretName,
			Key:  key,
		}
	}
}

func EtcdDataStore(object interface{}) {
	p, ok := object.(*proxyv1alpha2.Proxy)
	if !ok {
		return
	}

	p.Spec.DataStore = &proxyv1alpha2.ProxyDataStoreSpec{
		Etcd: &proxyv1alpha2.ProxyDataStoreEtcdSpec{
			Version: "v3.4.8",
		},
	}
}

func EtcdBackup(interval, maxBackups int) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Proxy)
		if !ok {
			return
		}

		if p.Spec.DataStore == nil || p.Spec.DataStore.Etcd == nil {
			return
		}
		if p.Spec.DataStore.Etcd.Backup == nil {
			p.Spec.DataStore.Etcd.Backup = &proxyv1alpha2.EtcdBackupSpec{}
		}
		p.Spec.DataStore.Etcd.Backup.IntervalInSecond = interval
		p.Spec.DataStore.Etcd.Backup.MaxBackups = maxBackups
	}
}

func EtcdBackupToMinIO(bucket, path string, secure bool, svcName, svcNamespace string, creds *proxyv1alpha2.AWSCredentialSelector) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Proxy)
		if !ok {
			return
		}

		if p.Spec.DataStore == nil || p.Spec.DataStore.Etcd == nil {
			return
		}
		if p.Spec.DataStore.Etcd.Backup == nil {
			p.Spec.DataStore.Etcd.Backup = &proxyv1alpha2.EtcdBackupSpec{}
		}
		if p.Spec.DataStore.Etcd.Backup.Storage == nil {
			p.Spec.DataStore.Etcd.Backup.Storage = &proxyv1alpha2.EtcdBackupStorageSpec{}
		}
		p.Spec.DataStore.Etcd.Backup.Storage.MinIO = &proxyv1alpha2.EtcdBackupMinIOSpec{
			ServiceSelector: &proxyv1alpha2.ObjectSelector{
				Name:      svcName,
				Namespace: svcNamespace,
			},
			CredentialSelector: creds,
			Bucket:             bucket,
			Path:               path,
			Secure:             secure,
		}
	}
}

func EtcdBackupToGCS(bucket, path string, creds *proxyv1alpha2.GCPCredentialSelector) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Proxy)
		if !ok {
			return
		}

		if p.Spec.DataStore == nil || p.Spec.DataStore.Etcd == nil {
			return
		}
		if p.Spec.DataStore.Etcd.Backup == nil {
			p.Spec.DataStore.Etcd.Backup = &proxyv1alpha2.EtcdBackupSpec{}
		}
		if p.Spec.DataStore.Etcd.Backup.Storage == nil {
			p.Spec.DataStore.Etcd.Backup.Storage = &proxyv1alpha2.EtcdBackupStorageSpec{}
		}
		p.Spec.DataStore.Etcd.Backup.Storage.GCS = &proxyv1alpha2.EtcdBackupGCSSpec{
			CredentialSelector: creds,
			Bucket:             bucket,
			Path:               path,
		}
	}
}

func EnableAntiAffinity(object interface{}) {
	p, ok := object.(*proxyv1alpha2.Proxy)
	if !ok {
		return
	}
	p.Spec.AntiAffinity = true
}

func ClientSecret(name, key string) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Proxy)
		if !ok {
			return
		}
		if p.Spec.IdentityProvider.ClientSecretRef == nil {
			p.Spec.IdentityProvider.ClientSecretRef = &proxyv1alpha2.SecretSelector{}
		}
		p.Spec.IdentityProvider.ClientSecretRef.Name = name
		p.Spec.IdentityProvider.ClientSecretRef.Key = key
	}
}

func Domain(v string) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Proxy)
		if !ok {
			return
		}

		p.Spec.Domain = v
	}
}

func RootUsers(users []string) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Proxy)
		if !ok {
			return
		}
		p.Spec.RootUsers = users
	}
}

func Version(v string) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Proxy)
		if !ok {
			return
		}
		p.Spec.Version = v
	}
}

func CookieSession(object interface{}) {
	p, ok := object.(*proxyv1alpha2.Proxy)
	if !ok {
		return
	}

	p.Spec.Session = proxyv1alpha2.SessionSpec{
		Type: config.SessionTypeSecureCookie,
	}
}

func BackendMatchLabelSelector(namespace string, label map[string]string) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Proxy)
		if !ok {
			return
		}
		p.Spec.BackendSelector = &proxyv1alpha2.LabelSelector{
			Namespace: namespace,
			LabelSelector: metav1.LabelSelector{
				MatchLabels: label,
			},
		}
	}
}

func RoleMatchLabelSelector(namespace string, label map[string]string) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Proxy)
		if !ok {
			return
		}
		p.Spec.RoleSelector = &proxyv1alpha2.LabelSelector{
			Namespace: namespace,
			LabelSelector: metav1.LabelSelector{
				MatchLabels: label,
			},
		}
	}
}

func RpcPermissionMatchLabelSelector(namespace string, label map[string]string) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Proxy)
		if !ok {
			return
		}
		p.Spec.RpcPermissionSelector = &proxyv1alpha2.LabelSelector{
			Namespace: namespace,
			LabelSelector: metav1.LabelSelector{
				MatchLabels: label,
			},
		}
	}
}

func BackendFactory(base *proxyv1alpha2.Backend, traits ...k8sfactory.Trait) *proxyv1alpha2.Backend {
	var b *proxyv1alpha2.Backend
	if base == nil {
		b = &proxyv1alpha2.Backend{}
	} else {
		b = base.DeepCopy()
	}
	if b.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(b)
		if err == nil && !unversioned && len(gvks) > 0 {
			b.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, trait := range traits {
		trait(b)
	}

	return b
}

func Layer(v string) k8sfactory.Trait {
	return func(object interface{}) {
		b, ok := object.(*proxyv1alpha2.Backend)
		if !ok {
			return
		}
		b.Spec.Layer = v
	}
}

func Permission(perm *proxyv1alpha2.Permission) k8sfactory.Trait {
	return func(object interface{}) {
		b, ok := object.(*proxyv1alpha2.Backend)
		if !ok {
			return
		}
		b.Spec.Permissions = append(b.Spec.Permissions, *perm)
	}
}

func FQDN(v string) k8sfactory.Trait {
	return func(object interface{}) {
		b, ok := object.(*proxyv1alpha2.Backend)
		if !ok {
			return
		}
		b.Spec.FQDN = v
	}
}

func DisableAuthn(object interface{}) {
	b, ok := object.(*proxyv1alpha2.Backend)
	if !ok {
		return
	}
	b.Spec.DisableAuthn = true
}

func HTTP(v []proxyv1alpha2.BackendHTTPSpec) k8sfactory.Trait {
	return func(object interface{}) {
		b, ok := object.(*proxyv1alpha2.Backend)
		if !ok {
			return
		}
		b.Spec.HTTP = v
	}
}

func AllowRootUser(object interface{}) {
	b, ok := object.(*proxyv1alpha2.Backend)
	if !ok {
		return
	}
	b.Spec.AllowRootUser = true
}

func PermissionFactory(base *proxyv1alpha2.Permission, traits ...k8sfactory.Trait) *proxyv1alpha2.Permission {
	var p *proxyv1alpha2.Permission
	if base == nil {
		p = &proxyv1alpha2.Permission{}
	} else {
		p = base.DeepCopy()
	}

	for _, trait := range traits {
		trait(p)
	}

	return p
}

func Name(v string) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Permission)
		if !ok {
			return
		}
		p.Name = v
	}
}

func Location(method, path string) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Permission)
		if !ok {
			return
		}

		var l proxyv1alpha2.Location
		switch method {
		case "Any":
			l.Any = path
		case http.MethodGet:
			l.Get = path
		case http.MethodPost:
			l.Post = path
		case http.MethodPut:
			l.Put = path
		case http.MethodDelete:
			l.Delete = path
		case http.MethodHead:
			l.Head = path
		case http.MethodConnect:
			l.Connect = path
		case http.MethodOptions:
			l.Options = path
		case http.MethodTrace:
			l.Trace = path
		case http.MethodPatch:
			l.Patch = path
		}
		p.Locations = append(p.Locations, l)
	}
}

func Webhook(t string) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Permission)
		if !ok {
			return
		}
		p.Webhook = t
	}
}

func GitHubWebhookConfiguration(v *proxyv1alpha2.GitHubHookConfiguration) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Permission)
		if !ok {
			return
		}
		p.WebhookConfiguration = &proxyv1alpha2.WebhookConfiguration{
			GitHub: v,
		}
	}
}

func RoleFactory(base *proxyv1alpha2.Role, traits ...k8sfactory.Trait) *proxyv1alpha2.Role {
	var r *proxyv1alpha2.Role
	if base == nil {
		r = &proxyv1alpha2.Role{}
	} else {
		r = base.DeepCopy()
	}
	if r.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(r)
		if err == nil && !unversioned && len(gvks) > 0 {
			r.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, trait := range traits {
		trait(r)
	}

	return r
}

func Title(v string) k8sfactory.Trait {
	return func(object interface{}) {
		r, ok := object.(*proxyv1alpha2.Role)
		if !ok {
			return
		}
		r.Spec.Title = v
	}
}

func Description(v string) k8sfactory.Trait {
	return func(object interface{}) {
		r, ok := object.(*proxyv1alpha2.Role)
		if !ok {
			return
		}
		r.Spec.Description = v
	}
}

func AllowDashboard(object interface{}) {
	r, ok := object.(*proxyv1alpha2.Role)
	if !ok {
		return
	}
	r.Spec.AllowDashboard = true
}

func RoleBindingFactory(base *proxyv1alpha2.RoleBinding, traits ...k8sfactory.Trait) *proxyv1alpha2.RoleBinding {
	var rb *proxyv1alpha2.RoleBinding
	if base == nil {
		rb = &proxyv1alpha2.RoleBinding{}
	} else {
		rb = base.DeepCopy()
	}
	if rb.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(rb)
		if err == nil && !unversioned && len(gvks) > 0 {
			rb.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, trait := range traits {
		trait(rb)
	}

	return rb
}

func Role(v *proxyv1alpha2.Role) k8sfactory.Trait {
	return func(object interface{}) {
		rb, ok := object.(*proxyv1alpha2.RoleBinding)
		if !ok {
			return
		}

		rb.RoleRef = proxyv1alpha2.RoleRef{
			Name:      v.Name,
			Namespace: v.Namespace,
		}
	}
}

func Subject(v runtime.Object, permission string) k8sfactory.Trait {
	return func(object interface{}) {
		rb, ok := object.(*proxyv1alpha2.RoleBinding)
		if !ok {
			return
		}

		switch obj := v.(type) {
		case *proxyv1alpha2.Backend:
			rb.Subjects = append(rb.Subjects, proxyv1alpha2.Subject{
				Kind:       "Backend",
				Name:       obj.Name,
				Namespace:  obj.Namespace,
				Permission: permission,
			})
		}
	}
}

func RpcPermissionFactory(base *proxyv1alpha2.RpcPermission, traits ...k8sfactory.Trait) *proxyv1alpha2.RpcPermission {
	var rp *proxyv1alpha2.RpcPermission
	if base == nil {
		rp = &proxyv1alpha2.RpcPermission{}
	} else {
		rp = base.DeepCopy()
	}
	if rp.GetObjectKind().GroupVersionKind().Kind == "" {
		gvks, unversioned, err := scheme.Scheme.ObjectKinds(rp)
		if err == nil && !unversioned && len(gvks) > 0 {
			rp.GetObjectKind().SetGroupVersionKind(gvks[0])
		}
	}

	for _, trait := range traits {
		trait(rp)
	}

	return rp
}

func Allow(rule string) k8sfactory.Trait {
	return func(object interface{}) {
		rp, ok := object.(*proxyv1alpha2.RpcPermission)
		if !ok {
			return
		}

		rp.Spec.Allow = append(rp.Spec.Allow, rule)
	}
}
