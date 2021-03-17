package proxy

import (
	proxyv1alpha2 "go.f110.dev/heimdallr/operator/pkg/api/proxy/v1alpha2"
	"go.f110.dev/heimdallr/operator/pkg/client/versioned/scheme"
	"go.f110.dev/heimdallr/pkg/config"
)

type Trait func(p *proxyv1alpha2.Proxy)

func Factory(base *proxyv1alpha2.Proxy, traits ...Trait) *proxyv1alpha2.Proxy {
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

func Namespace(v string) Trait {
	return func(p *proxyv1alpha2.Proxy) {
		p.SetNamespace(v)
	}
}

func Name(v string) Trait {
	return func(p *proxyv1alpha2.Proxy) {
		p.SetName(v)
	}
}

func EtcdDataStore(p *proxyv1alpha2.Proxy) {
	p.Spec.DataStore = &proxyv1alpha2.ProxyDataStoreSpec{
		Etcd: &proxyv1alpha2.ProxyDataStoreEtcdSpec{
			Version:      "v3.4.8",
			AntiAffinity: true,
		},
	}
}

func ClientSecret(name, key string) Trait {
	return func(p *proxyv1alpha2.Proxy) {
		p.Spec.IdentityProvider.ClientSecretRef.Name = name
		p.Spec.IdentityProvider.ClientSecretRef.Key = key
	}
}

func RootUsers(users []string) Trait {
	return func(p *proxyv1alpha2.Proxy) {
		p.Spec.RootUsers = users
	}
}

func Version(v string) Trait {
	return func(p *proxyv1alpha2.Proxy) {
		p.Spec.Version = v
	}
}

func CookieSession(e *proxyv1alpha2.Proxy) {
	e.Spec.Session = proxyv1alpha2.SessionSpec{
		Type: config.SessionTypeSecureCookie,
	}
}
