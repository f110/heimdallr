package configutil

import (
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/pkg/config/configv2"
)

func ReadConfig(filename string) (*configv2.Config, error) {
	return ReadConfigV2(filename)
}

func ReadConfigV2(filename string) (*configv2.Config, error) {
	a, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(a)

	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	conf := &configv2.Config{
		AccessProxy: &configv2.AccessProxy{
			HTTP: &configv2.AuthProxyHTTP{
				Bind:            ":4000",
				BindHttp:        ":4001",
				BindInternalApi: ":4004",
				ServerName:      "local-proxy.f110.dev:4000",
			},
		},
		Logger: &configv2.Logger{
			Level:    "debug",
			Encoding: "console",
		},
		Dashboard: &configv2.Dashboard{
			Bind: "",
			Template: &configv2.Template{
				Loader: "embed",
				Dir:    "tmpl/dashboard",
			},
		},
		Datastore: &configv2.Datastore{},
		IdentityProvider: &configv2.IdentityProvider{
			RedirectUrl: "https://local-proxy.f110.dev:4000/auth/callback",
		},
	}
	if err := yaml.Unmarshal(b, conf); err != nil {
		return nil, xerrors.Errorf("config: file parse error: %v", err)
	}
	if conf.AccessProxy != nil {
		if err := conf.AccessProxy.Load(dir); err != nil {
			return nil, err
		}
	}
	if conf.AuthorizationEngine != nil {
		if err := conf.AuthorizationEngine.Load(dir); err != nil {
			return nil, err
		}
	}
	if conf.IdentityProvider != nil {
		if err := conf.IdentityProvider.Load(dir); err != nil {
			return nil, err
		}
	}
	if conf.Datastore != nil && conf.Datastore.DatastoreEtcd != nil && conf.Datastore.DatastoreEtcd.RawUrl != "" {
		if err := conf.Datastore.Load(dir); err != nil {
			return nil, err
		}
	}
	if conf.CertificateAuthority != nil {
		if err := conf.CertificateAuthority.Load(dir); err != nil {
			return nil, err
		}
	}
	if conf.Dashboard != nil {
		if err := conf.Dashboard.Load(dir); err != nil {
			return nil, err
		}
	}

	return conf, nil
}
