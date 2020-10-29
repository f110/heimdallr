package configreader

import (
	"crypto/ecdsa"
	"crypto/x509"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/config/configv2"

	"go.f110.dev/heimdallr/pkg/config"
)

func TestReadConfigV1(t *testing.T) {
	roleBuf := `- name: admin
  title: administrator
  description: for administrator
  bindings:
    - backend: test.local-proxy.f110.dev
      permission: all
`
	proxyBuf := `
- name: test.local-proxy.f110.dev
  upstream: http://localhost:4501
  permissions:
    - name: all
      locations:
        - get: /get
          post: /post
          put: /put
          delete: /delete
          head: /head
          connect: /connect
          options: /options
          trace: /trace
          patch: /patch
- name: content.local-proxy.f110.dev
  upstream: http://localhost:4502
  permissions:
    - name: all
      locations:
        - get: /
`
	b := `
general:
  role_file: ./roles.yaml
  proxy_file: ./proxies.yaml
  certificate_authority:
    cert_file: ./ca.crt
    key_file: ./ca.key
datastore:
  url: etcd://embed
  data_dir: ./data
frontend_proxy:
  bind: :4000
  cert_file: ./tls.crt
  key_file: ./tls.key
logger:
  level: debug
  encoding: console
`

	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	f, err := ioutil.TempFile(tmpDir, "")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(b)
	f.Sync()
	if err := ioutil.WriteFile(filepath.Join(tmpDir, "roles.yaml"), []byte(roleBuf), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(filepath.Join(tmpDir, "proxies.yaml"), []byte(proxyBuf), 0644); err != nil {
		t.Fatal(err)
	}
	caCert, privateKey, err := cert.CreateCertificateAuthorityForConfig(
		&configv2.Config{
			CertificateAuthority: &configv2.CertificateAuthority{
				Organization:     "Test",
				OrganizationUnit: "Test Unit",
				Country:          "JP",
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	privKey, err := x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.PemEncode(filepath.Join(tmpDir, "ca.key"), "EC PRIVATE KEY", privKey, nil); err != nil {
		t.Fatal(err)
	}
	if err := cert.PemEncode(filepath.Join(tmpDir, "ca.crt"), "CERTIFICATE", caCert.Raw, nil); err != nil {
		t.Fatal(err)
	}

	c, privateKey, err := cert.GenerateServerCertificate(caCert, privateKey, []string{"test.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	privKey, err = x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.PemEncode(filepath.Join(tmpDir, "tls.key"), "EC PRIVATE KEY", privKey, nil); err != nil {
		t.Fatal(err)
	}
	if err := cert.PemEncode(filepath.Join(tmpDir, "tls.crt"), "CERTIFICATE", c.Raw, nil); err != nil {
		t.Fatal(err)
	}

	conf, err := ReadConfigV1(f.Name())
	assert.NoError(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if conf.Datastore == nil {
		t.Fatal("yaml parse error or something")
	}
	if conf.Datastore.Url.Scheme != "etcd" {
		t.Errorf("datastore url is expected etcd: %s", conf.Datastore.Url.Scheme)
	}
	if conf.Datastore.Url.Hostname() != "embed" {
		t.Errorf("datastore host is expect embed: %s", conf.Datastore.Url.Hostname())
	}
	if conf.Logger == nil {
		t.Fatal("yaml parse error or something")
	}
	if conf.Logger.Level != "debug" {
		t.Errorf("expect logger level is debug: %s", conf.Logger.Level)
	}
	if conf.Logger.Encoding != "console" {
		t.Errorf("expect logger encoding is console: %s", conf.Logger.Encoding)
	}
	if conf.Datastore.DataDir != filepath.Join(tmpDir, "data") {
		t.Errorf("datastore.data expect %s: %s", filepath.Join(tmpDir, "data"), conf.Datastore.DataDir)
	}

	err = ioutil.WriteFile(filepath.Join(tmpDir, "data", config.EmbedEtcdUrlFilename), []byte("etcd://localhost:60000"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	conf, err = ReadConfigV1(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if conf.Datastore.EtcdUrl.Host != "localhost:60000" {
		t.Errorf("failed read previous etcd url: %s", conf.Datastore.EtcdUrl.String())
	}
}

func TestReadConfigFromFile(t *testing.T) {
	conf, err := ReadConfigV1("./testdata/config_debug.yaml")
	require.NoError(t, err)

	backends := make(map[string]*config.Backend)
	for _, v := range conf.General.GetAllBackends() {
		backends[v.Name] = v
	}
	roles := make(map[string]*config.Role)
	for _, v := range conf.General.GetAllRoles() {
		roles[v.Name] = v
	}

	assert.Contains(t, backends, "dashboard")
	assert.True(t, backends["dashboard"].AllowRootUser)
	assert.Contains(t, backends, "test")
	assert.Equal(t, backends["test"].WebHook, "github")
	assert.Contains(t, backends, "test-agent")
	assert.True(t, backends["test-agent"].Agent)
	assert.Contains(t, backends, "short")
	assert.True(t, backends["short"].DisableAuthn)
	assert.Equal(t, backends["short"].FQDN, "short.f110.dev")
	assert.Contains(t, backends, "ssh")
	assert.Equal(t, backends["ssh"].SocketTimeout.Duration, 10*time.Second)

	assert.Contains(t, roles, "user")
}

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
	conf, err := ReadConfig("./testdata/config_debug.yaml")
	require.NoError(t, err)
	require.IsType(t, &configv2.Config{}, conf)

	t.Run("Dashboard", func(t *testing.T) {
		conf, err := ReadConfig("./testdata/config_v1_dashboard.yaml")
		require.NoError(t, err)

		require.NotNil(t, conf.AccessProxy)
		require.NotNil(t, conf.AccessProxy.HTTP)
		require.NotNil(t, conf.RPCServer)
		assert.Empty(t, conf.AccessProxy.HTTP.Bind)
		assert.Empty(t, conf.AccessProxy.HTTP.BindInternalApi)
		assert.Empty(t, conf.RPCServer.Bind)
		assert.Equal(t, "./internal_token", conf.Dashboard.TokenFile)
		assert.Equal(t, "127.0.0.1:4001", conf.Dashboard.RPCServer)
		assert.Equal(t, ":4100", conf.Dashboard.Bind)
		assert.Equal(t, "./ca.crt", conf.CertificateAuthority.CertFile)
	})

	t.Run("RPCServer", func(t *testing.T) {
		conf, err := ReadConfig("./testdata/config_v1_rpcserver.yaml")
		require.NoError(t, err)

		require.NotNil(t, conf.AccessProxy)
		require.NotNil(t, conf.AccessProxy.HTTP)
		require.NotNil(t, conf.RPCServer)
		require.NotNil(t, conf.AuthorizationEngine)
		require.NotNil(t, conf.Datastore)
		require.NotNil(t, conf.Datastore.DatastoreEtcd)
		require.Nil(t, conf.Datastore.DatastoreMySQL)
		require.NotNil(t, conf.Dashboard)
		assert.Equal(t, ":4001", conf.RPCServer.Bind)
		assert.Equal(t, "./ca.crt", conf.CertificateAuthority.CertFile)
		assert.Equal(t, "./ca.key", conf.CertificateAuthority.KeyFile)
		assert.Equal(t, "test", conf.CertificateAuthority.Organization)
		assert.Equal(t, "dev", conf.CertificateAuthority.OrganizationUnit)
		assert.Equal(t, "jp", conf.CertificateAuthority.Country)
		assert.Contains(t, conf.AuthorizationEngine.RoleFile, "/roles.yaml") // RoleFile is expanded.
		assert.Contains(t, conf.AuthorizationEngine.RPCPermissionFile, "/rpc_permissions.yaml")
		assert.Equal(t, []string{"fmhrit@gmail.com"}, conf.AuthorizationEngine.RootUsers)
		assert.Equal(t, "etcd://localhost:2379", conf.Datastore.DatastoreEtcd.RawUrl)
		assert.Empty(t, conf.Dashboard.Bind)
	})

	t.Run("Proxy", func(t *testing.T) {
		conf, err := ReadConfig("./testdata/config_v1_proxy.yaml")
		require.NoError(t, err)

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
		assert.Equal(t, ":4001", conf.AccessProxy.HTTP.BindHttp)
		assert.Equal(t, ":4003", conf.AccessProxy.HTTP.BindInternalApi)
		assert.Equal(t, "test.f110.dev:4000", conf.AccessProxy.HTTP.ServerName)
		assert.Equal(t, "./privatekey.pem", conf.AccessProxy.Credential.SigningPrivateKeyFile)
		assert.Equal(t, "./internal_token", conf.AccessProxy.Credential.InternalTokenFile)
		assert.Equal(t, "./github_webhook_secret", conf.AccessProxy.Credential.GithubWebHookSecretFile)
		assert.True(t, conf.AccessProxy.HTTP.ExpectCT)
		assert.Equal(t, "secure_cookie", conf.AccessProxy.HTTP.Session.Type)
		assert.Equal(t, "./cookie_secret", conf.AccessProxy.HTTP.Session.KeyFile)
		assert.Contains(t, conf.AccessProxy.HTTP.Certificate.CertFile, "/tls.crt")
		assert.Contains(t, conf.AccessProxy.HTTP.Certificate.KeyFile, "/tls.key")
		assert.Contains(t, conf.AccessProxy.ProxyFile, "/proxies.yaml")
		assert.Contains(t, conf.AuthorizationEngine.RoleFile, "/roles.yaml")
		assert.Contains(t, conf.AuthorizationEngine.RPCPermissionFile, "/rpc_permissions.yaml")
		assert.Equal(t, []string{"fmhrit@gmail.com"}, conf.AuthorizationEngine.RootUsers)
		assert.Equal(t, "127.0.0.1:4001", conf.AccessProxy.RPCServer)
		assert.Equal(t, "./ca.crt", conf.CertificateAuthority.CertFile)
		assert.Empty(t, conf.RPCServer.Bind)
		assert.Equal(t, "google", conf.IdentityProvider.Provider)
		assert.Equal(t, "70353433905-pqk31pc51d76hnk225tssjh9mkaof3da.apps.googleusercontent.com", conf.IdentityProvider.ClientId)
		assert.Equal(t, "./client_secret", conf.IdentityProvider.ClientSecretFile)
		assert.Equal(t, []string{"email"}, conf.IdentityProvider.ExtraScopes)
		assert.Equal(t, "https://test.f110.dev:4000/auth/callback", conf.IdentityProvider.RedirectUrl)
		assert.Equal(t, "etcds://localhost:2379", conf.Datastore.DatastoreEtcd.RawUrl)
		assert.Equal(t, "./ca.crt", conf.Datastore.DatastoreEtcd.CACertFile)
		assert.Equal(t, "./tls.crt", conf.Datastore.DatastoreEtcd.CertFile)
		assert.Equal(t, "./tls.key", conf.Datastore.DatastoreEtcd.KeyFile)
		assert.Empty(t, conf.Dashboard.Bind)
	})
}
