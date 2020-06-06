package configreader

import (
	"io/ioutil"
	"path/filepath"

	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/pkg/config"
)

func ReadConfig(filename string) (*config.Config, error) {
	a, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(a)

	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	conf := &config.Config{
		General: &config.General{
			Enable:          true,
			Bind:            ":4000",
			BindHttp:        ":4001",
			BindInternalApi: ":4004",
			ServerName:      "local-proxy.f110.dev:4000",
		},
		Logger: &config.Logger{
			Level:    "debug",
			Encoding: "console",
		},
		Dashboard: &config.Dashboard{
			Enable: false,
			Bind:   ":4100",
			Template: &config.Template{
				Loader: "embed",
				Dir:    "tmpl/dashboard",
			},
		},
		Datastore: &config.Datastore{
			Namespace: "/lp",
		},
		RPCServer: &config.RPCServer{
			Enable: false,
		},
		FrontendProxy: &config.FrontendProxy{},
		IdentityProvider: &config.IdentityProvider{
			RedirectUrl: "https://local-proxy.f110.dev:4000/auth/callback",
		},
	}
	if err := yaml.Unmarshal(b, conf); err != nil {
		return nil, xerrors.Errorf("config: file parse error: %v", err)
	}
	if conf.General != nil {
		if err := conf.General.Inflate(dir); err != nil {
			return nil, err
		}
	}
	if conf.IdentityProvider != nil {
		if err := conf.IdentityProvider.Inflate(dir); err != nil {
			return nil, err
		}
	}
	if conf.Datastore != nil && conf.Datastore.RawUrl != "" {
		if err := conf.Datastore.Inflate(dir); err != nil {
			return nil, err
		}
	}
	if conf.FrontendProxy != nil {
		if err := conf.FrontendProxy.Inflate(dir); err != nil {
			return nil, err
		}
	}
	if conf.Dashboard != nil {
		if err := conf.Dashboard.Inflate(dir); err != nil {
			return nil, err
		}
	}

	return conf, nil
}
