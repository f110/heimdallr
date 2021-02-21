package configutil

import (
	"net/url"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/config/configv2"
)

func ReadConfig(filename string) (*configv2.Config, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	confv2 := &configv2.Config{}
	if err := yaml.Unmarshal(b, confv2); err == nil {
		if confv2.AccessProxy == nil && confv2.CertificateAuthority == nil {
			confv1, err := ReadConfigV1(filename)
			if err != nil {
				return nil, xerrors.Errorf(": %w", err)
			}
			return V1ToV2(confv1), nil
		}
	}

	return ReadConfigV2(filename)
}

func ReadConfigV1(filename string) (*config.Config, error) {
	a, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(a)

	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	confv2 := &configv2.Config{}
	if err := yaml.Unmarshal(b, confv2); err == nil {
		if confv2.AccessProxy != nil || confv2.CertificateAuthority != nil {
			return nil, xerrors.Errorf("config: %s is v2 format", filename)
		}
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

func V1ToV2(in *config.Config) *configv2.Config {
	out := &configv2.Config{
		AccessProxy: &configv2.AccessProxy{
			HTTP: &configv2.AuthProxyHTTP{
				Session: &configv2.Session{},
			},
			Credential: &configv2.Credential{},
		},
		RPCServer:            &configv2.RPCServer{},
		Dashboard:            &configv2.Dashboard{},
		CertificateAuthority: &configv2.CertificateAuthority{},
		AuthorizationEngine: &configv2.AuthorizationEngine{
			RoleFile:          in.General.RoleFile,
			RPCPermissionFile: in.General.RpcPermissionFile,
			RootUsers:         in.General.RootUsers,
		},
		Datastore:        &configv2.Datastore{},
		IdentityProvider: &configv2.IdentityProvider{},
		Logger:           &configv2.Logger{},
	}
	if in.General.CertificateAuthority != nil {
		out.CertificateAuthority = &configv2.CertificateAuthority{
			Local: &configv2.CertificateAuthorityLocal{
				CertFile:         in.General.CertificateAuthority.CertFile,
				KeyFile:          in.General.CertificateAuthority.KeyFile,
				Organization:     in.General.CertificateAuthority.Organization,
				OrganizationUnit: in.General.CertificateAuthority.OrganizationUnit,
				Country:          in.General.CertificateAuthority.Country,
			},
		}
	}
	if in.General.Enable {
		out.AccessProxy = &configv2.AccessProxy{
			HTTP: &configv2.AuthProxyHTTP{
				Bind:            in.General.Bind,
				BindHttp:        in.General.BindHttp,
				BindInternalApi: in.General.BindInternalApi,
				ServerName:      in.General.ServerName,
				Certificate: &configv2.Certificate{
					CertFile: in.General.CertFile,
					KeyFile:  in.General.KeyFile,
				},
			},
			Credential: &configv2.Credential{
				SigningPrivateKeyFile: in.General.SigningPrivateKeyFile,
				InternalTokenFile:     in.General.InternalTokenFile,
			},
			RPCServer: in.General.RpcTarget,
			ProxyFile: in.General.ProxyFile,
		}
		if in.FrontendProxy != nil {
			if in.FrontendProxy.Session != nil {
				out.AccessProxy.HTTP.Session = &configv2.Session{
					Type:    in.FrontendProxy.Session.Type,
					KeyFile: in.FrontendProxy.Session.KeyFile,
				}
			}
			out.AccessProxy.HTTP.ExpectCT = in.FrontendProxy.ExpectCT
			out.AccessProxy.Credential.GithubWebHookSecretFile = in.FrontendProxy.GithubWebHookSecretFile
		}
	}
	if in.Dashboard.Enable {
		out.Dashboard = &configv2.Dashboard{
			Bind:      in.Dashboard.Bind,
			RPCServer: in.General.RpcTarget,
			TokenFile: in.General.InternalTokenFile,
			Template: &configv2.Template{
				Loader: in.Dashboard.Template.Loader,
				Dir:    in.Dashboard.Template.Dir,
			},
		}
	}
	if in.RPCServer != nil && in.RPCServer.Enable {
		out.RPCServer = &configv2.RPCServer{
			Bind: in.RPCServer.Bind,
		}
	}
	if in.Datastore != nil && in.Datastore.RawUrl != "" {
		u, err := url.Parse(in.Datastore.RawUrl)
		if err == nil {
			switch u.Scheme {
			case "etcd", "etcds":
				out.Datastore.DatastoreEtcd = &configv2.DatastoreEtcd{
					RawUrl:     in.Datastore.RawUrl,
					DataDir:    in.Datastore.DataDir,
					Namespace:  in.Datastore.Namespace,
					CACertFile: in.Datastore.CACertFile,
					CertFile:   in.Datastore.CertFile,
					KeyFile:    in.Datastore.KeyFile,
				}
			}
		}
	}
	if in.Logger != nil {
		out.Logger = &configv2.Logger{
			Level:    in.Logger.Level,
			Encoding: in.Logger.Encoding,
		}
	}
	if in.IdentityProvider != nil {
		out.IdentityProvider = &configv2.IdentityProvider{
			Provider:         in.IdentityProvider.Provider,
			Issuer:           in.IdentityProvider.Issuer,
			ClientId:         in.IdentityProvider.ClientId,
			ClientSecretFile: in.IdentityProvider.ClientSecretFile,
			ExtraScopes:      in.IdentityProvider.ExtraScopes,
			Domain:           in.IdentityProvider.Domain,
			RedirectUrl:      in.IdentityProvider.RedirectUrl,
		}
	}

	return out
}
