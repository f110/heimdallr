package proxy

import (
	proxyv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha2"
	"go.f110.dev/heimdallr/operator/pkg/client/versioned/scheme"
	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/k8s/k8sfactory"
)

func Factory(base *proxyv1alpha2.Proxy, traits ...k8sfactory.Trait) *proxyv1alpha2.Proxy {
	var p *proxyv1alpha2.Proxy
	if base == nil {
		p = &proxyv1alpha2.Proxy{}
	} else {
		p = base
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

func EtcdDataStore(object interface{}) {
	p, ok := object.(*proxyv1alpha2.Proxy)
	if !ok {
		return
	}

	p.Spec.DataStore = &proxyv1alpha2.ProxyDataStoreSpec{
		Etcd: &proxyv1alpha2.ProxyDataStoreEtcdSpec{
			Version:      "v3.4.8",
			AntiAffinity: true,
		},
	}
}

func ClientSecret(name, key string) k8sfactory.Trait {
	return func(object interface{}) {
		p, ok := object.(*proxyv1alpha2.Proxy)
		if !ok {
			return
		}
		p.Spec.IdentityProvider.ClientSecretRef.Name = name
		p.Spec.IdentityProvider.ClientSecretRef.Key = key
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

func BackendFactory(base *proxyv1alpha2.Backend, traits ...k8sfactory.Trait) *proxyv1alpha2.Backend {
	var b *proxyv1alpha2.Backend
	if base == nil {
		b = &proxyv1alpha2.Backend{}
	} else {
		b = base
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

func HTTP(v []*proxyv1alpha2.BackendHTTPSpec) k8sfactory.Trait {
	return func(object interface{}) {
		b, ok := object.(*proxyv1alpha2.Backend)
		if !ok {
			return
		}
		b.Spec.HTTP = v
	}
}
