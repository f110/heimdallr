package configutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.f110.dev/heimdallr/pkg/config/configv2"
)

func TestReadConfigV2(t *testing.T) {
	conf, err := ReadConfigV2("./testdata/config_v2.yaml")
	require.NoError(t, err)

	assert.NotNil(t, conf.AccessProxy)
	assert.NotNil(t, conf.AuthorizationEngine)
	assert.NotNil(t, conf.RPCServer)
	assert.NotNil(t, conf.Dashboard)
	assert.NotNil(t, conf.CertificateAuthority)
	assert.NotNil(t, conf.IdentityProvider)
	assert.NotNil(t, conf.Datastore.DatastoreEtcd)
	assert.Nil(t, conf.Datastore.DatastoreMySQL)
}

func TestReadConfig(t *testing.T) {
	conf, err := ReadConfig("./testdata/config_v2.yaml")
	require.NoError(t, err)
	require.IsType(t, &configv2.Config{}, conf)

	require.NotNil(t, conf.AccessProxy)
	require.NotNil(t, conf.AccessProxy.HTTP)
	require.NotNil(t, conf.AccessProxy.HTTP.Certificate)
	require.NotNil(t, conf.AccessProxy.Credential)
	require.NotNil(t, conf.AccessProxy.HTTP.Session)
	require.NotNil(t, conf.IdentityProvider)
	require.NotNil(t, conf.RPCServer)
	require.NotNil(t, conf.AuthorizationEngine)
	require.NotNil(t, conf.Datastore)
	require.NotNil(t, conf.Datastore.DatastoreEtcd)
	require.Nil(t, conf.Datastore.DatastoreMySQL)
	require.NotNil(t, conf.Dashboard)
	assert.Equal(t, ":4000", conf.AccessProxy.HTTP.Bind)
	assert.Equal(t, ":4002", conf.AccessProxy.HTTP.BindHttp)
	assert.Equal(t, ":4004", conf.AccessProxy.HTTP.BindInternalApi)
	assert.Equal(t, "test.f110.dev:4000", conf.AccessProxy.HTTP.ServerName)
	assert.Equal(t, "./privatekey.pem", conf.AccessProxy.Credential.SigningPrivateKeyFile)
	assert.Equal(t, "./internal_token", conf.AccessProxy.Credential.InternalTokenFile)
	assert.Equal(t, "./github_webhook_secret", conf.AccessProxy.Credential.GithubWebHookSecretFile)
	assert.Equal(t, "secure_cookie", conf.AccessProxy.HTTP.Session.Type)
	assert.Equal(t, "./cookie_secret", conf.AccessProxy.HTTP.Session.KeyFile)
	assert.Contains(t, conf.AccessProxy.HTTP.Certificate.CertFile, "/tls.crt")
	assert.Contains(t, conf.AccessProxy.HTTP.Certificate.KeyFile, "/tls.key")
	assert.Contains(t, conf.AccessProxy.ProxyFile, "/proxies.yaml")
	assert.Contains(t, conf.AuthorizationEngine.RoleFile, "/roles.yaml")
	assert.Contains(t, conf.AuthorizationEngine.RPCPermissionFile, "/rpc_permissions.yaml")
	assert.Equal(t, []string{"fmhrit@gmail.com"}, conf.AuthorizationEngine.RootUsers)
	assert.Equal(t, "127.0.0.1:4001", conf.AccessProxy.RPCServer)
	assert.Equal(t, "./ca.crt", conf.CertificateAuthority.Local.CertFile)
	assert.Equal(t, ":4001", conf.RPCServer.Bind)
	assert.Equal(t, "google", conf.IdentityProvider.Provider)
	assert.Equal(t, "70353433905-pqk31pc51d76hnk225tssjh9mkaof3da.apps.googleusercontent.com", conf.IdentityProvider.ClientId)
	assert.Equal(t, "./client_secret", conf.IdentityProvider.ClientSecretFile)
	assert.Equal(t, []string{"email"}, conf.IdentityProvider.ExtraScopes)
	assert.Equal(t, "https://test.f110.dev:4000/auth/callback", conf.IdentityProvider.RedirectUrl)
	assert.Equal(t, "etcd://localhost:2379", conf.Datastore.DatastoreEtcd.RawUrl)
	assert.Equal(t, ":4100", conf.Dashboard.Bind)

	t.Run("RPCServer", func(t *testing.T) {
		conf, err := ReadConfig("./testdata/config_v2_rpc_server.yaml")
		require.NoError(t, err)

		require.NotNil(t, conf.AccessProxy)
		require.NotNil(t, conf.AccessProxy.HTTP)
		require.NotNil(t, conf.RPCServer)
		require.Nil(t, conf.AuthorizationEngine)
		require.NotNil(t, conf.Datastore)
		require.NotNil(t, conf.Datastore.DatastoreEtcd)
		require.Nil(t, conf.Datastore.DatastoreMySQL)
		require.NotNil(t, conf.Dashboard)
		assert.Equal(t, ":4001", conf.RPCServer.Bind)
		assert.Equal(t, "./ca.crt", conf.CertificateAuthority.Local.CertFile)
		assert.Equal(t, "./ca.key", conf.CertificateAuthority.Local.KeyFile)
		assert.Equal(t, "test", conf.CertificateAuthority.Local.Organization)
		assert.Equal(t, "dev", conf.CertificateAuthority.Local.OrganizationUnit)
		assert.Equal(t, "jp", conf.CertificateAuthority.Local.Country)
		assert.Equal(t, "etcd://localhost:2379", conf.Datastore.DatastoreEtcd.RawUrl)
		assert.Empty(t, conf.Dashboard.Bind)
	})
}
