package authproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.f110.dev/heimdallr/pkg/auth"
	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/database/memory"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
	"go.f110.dev/heimdallr/pkg/session"
)

func newTLSConnectionState() *tls.ConnectionState {
	return &tls.ConnectionState{HandshakeComplete: true}
}

func TestNewHttpProxy(t *testing.T) {
	conf := &configv2.Config{
		Logger: &configv2.Logger{},
	}
	c := rpcclient.NewWithClient(nil, nil, nil, nil)
	p := NewHttpProxy(conf, nil, c)

	assert.NotNil(t, p, "NewHttpProxy should return a value")
}

func TestHttpProxy_ServeHTTP(t *testing.T) {
	u := memory.NewUserDatabase()
	_ = u.Set(nil, &database.User{Id: "foobarbaz@example.com", Roles: []string{"test", "unknown"}})
	backends := []*configv2.Backend{
		{
			Name: "test",
			HTTP: []*configv2.HTTPBackend{},
			Permissions: []*configv2.Permission{
				{Name: "all", Locations: []configv2.Location{{Get: "/"}}},
			},
		},
		{
			Name: "webhook",
			HTTP: []*configv2.HTTPBackend{{Path: "/github"}},
			Permissions: []*configv2.Permission{
				{Name: "github", WebHook: "github", Locations: []configv2.Location{{Post: "/github"}}},
			},
		},
		{
			Name: "slack",
			HTTP: []*configv2.HTTPBackend{{Path: "/command"}},
			Permissions: []*configv2.Permission{
				{Name: "slack", WebHook: "slack", Locations: []configv2.Location{{Post: "/command"}}},
			},
		},
		{
			Name:      "http",
			AllowHttp: true,
			Permissions: []*configv2.Permission{
				{Name: "all", Locations: []configv2.Location{{Any: "/"}}},
			},
		},
	}
	roles := []*configv2.Role{
		{
			Name: "test",
			Bindings: []*configv2.Binding{
				{Backend: "test", Permission: "all"},
				{Backend: "http", Permission: "all"},
			},
		},
	}
	rpcPermissions := []*configv2.RPCPermission{}

	signReqKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signReqPubKey := signReqKey.PublicKey
	conf := &configv2.Config{
		AccessProxy: &configv2.AccessProxy{
			ServerNameHost: "example.com",
			Credential: &configv2.Credential{
				SigningPrivateKey:   signReqKey,
				SigningPublicKey:    signReqPubKey,
				GithubWebhookSecret: []byte("test"),
			},
		},
		AuthorizationEngine: &configv2.AuthorizationEngine{},
		Logger: &configv2.Logger{
			Level: "debug",
		},
	}
	s, err := session.NewSecureCookieStore([]byte("test"), []byte("testtesttesttesttesttesttesttest"), "example.com")
	require.NoError(t, err)
	err = conf.AccessProxy.Setup(backends)
	require.NoError(t, err)
	err = conf.AuthorizationEngine.Setup(roles, rpcPermissions)
	require.NoError(t, err)
	auth.Init(conf, s, u, nil, nil)
	err = logger.Init(conf.Logger)
	require.NoError(t, err)

	c := rpcclient.NewWithClient(nil, nil, nil, nil)
	p := NewHttpProxy(conf, nil, c)

	t.Run("Session not found", func(t *testing.T) {
		t.Parallel()

		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://test.example.com", nil)
		req.TLS = newTLSConnectionState()
		p.ServeHTTP(context.Background(), recorder, req)

		res := recorder.Result()
		assert.Equal(t, http.StatusSeeOther, res.StatusCode)
	})

	t.Run("User not found", func(t *testing.T) {
		t.Parallel()

		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://test.example.com", nil)
		req.TLS = newTLSConnectionState()
		cookie, err := s.Cookie(session.New("foobar@example.com"))
		require.NoError(t, err)
		req.AddCookie(cookie)
		p.ServeHTTP(context.Background(), recoder, req)

		res := recoder.Result()
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	})

	t.Run("Host not found", func(t *testing.T) {
		t.Parallel()

		defer func() {
			err := recover()
			require.NotNil(t, err, "ServeHTTP should panic")
			require.Equal(t, http.ErrAbortHandler, err)
		}()

		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://panic.example.com", nil)
		req.TLS = newTLSConnectionState()
		p.ServeHTTP(context.Background(), recoder, req)
	})

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://test.example.com/", nil)
		req.TLS = newTLSConnectionState()
		cookie, err := s.Cookie(session.New("foobarbaz@example.com"))
		require.NoError(t, err)
		req.AddCookie(cookie)
		p.ServeHTTP(context.Background(), recoder, req)

		res := recoder.Result()
		assert.Equal(t, http.StatusBadGateway, res.StatusCode)
	})

	t.Run("Success via http", func(t *testing.T) {
		t.Parallel()

		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://http.example.com/", nil)
		cookie, err := s.Cookie(session.New("foobarbaz@example.com"))
		require.NoError(t, err)
		req.AddCookie(cookie)
		p.ServeHTTP(context.Background(), recoder, req)

		res := recoder.Result()
		assert.Equal(t, http.StatusBadGateway, res.StatusCode)
	})

	t.Run("Backend is not allowed http access", func(t *testing.T) {
		t.Parallel()

		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://test.example.com/", nil)
		cookie, err := s.Cookie(session.New("foobarbaz@example.com"))
		require.NoError(t, err)
		req.AddCookie(cookie)
		p.ServeHTTP(context.Background(), recoder, req)

		res := recoder.Result()
		assert.Equal(t, http.StatusForbidden, res.StatusCode)
	})

	t.Run("Webhook from github without signature", func(t *testing.T) {
		t.Parallel()

		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://webhook.example.com/github", nil)
		p.ServeGithubWebHook(context.Background(), recoder, req)

		res := recoder.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("Webhook from github with valid signature", func(t *testing.T) {
		t.Parallel()

		body := strings.NewReader("{}")
		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "https://webhook.example.com/github", body)
		// req.TLS = newTLSConnectionState()
		mac := hmac.New(sha1.New, conf.AccessProxy.Credential.GithubWebhookSecret)
		mac.Write([]byte("{}"))
		sign := mac.Sum(nil)
		req.Header.Set("X-Hub-Signature", "sha1="+hex.EncodeToString(sign))
		p.ServeGithubWebHook(context.Background(), recoder, req)

		res := recoder.Result()
		assert.Equal(t, http.StatusBadGateway, res.StatusCode)
	})

	t.Run("Webhook from slack without client certificate", func(t *testing.T) {
		t.Parallel()

		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://slack.example.com/command", nil)
		p.ServeSlackWebHook(context.Background(), recoder, req)

		res := recoder.Result()
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	})

	t.Run("Webhook from slack with invalid client certificate", func(t *testing.T) {
		t.Parallel()

		caCert, caPrivateKey, err := cert.CreateCertificateAuthority("test", "", "", "jp", "ecdsa")
		require.NoError(t, err)
		ca := &configv2.CertificateAuthority{
			Local: &configv2.CertificateAuthorityLocal{
				PrivateKey: caPrivateKey,
			},
			Certificate: caCert,
		}
		serial, err := cert.NewSerialNumber()
		require.NoError(t, err)
		_, clientCert, err := cert.CreateNewCertificateForClient(pkix.Name{CommonName: "slack.f110.dev"}, serial, "ecdsa", 224, "", ca)
		require.NoError(t, err)

		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://slack.example.com/command", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
		p.ServeSlackWebHook(context.Background(), recoder, req)

		res := recoder.Result()
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	})

	t.Run("Webhook from slack with client certificate", func(t *testing.T) {
		t.Parallel()

		caCert, caPrivateKey, err := cert.CreateCertificateAuthority("test", "", "", "jp", "ecdsa")
		require.NoError(t, err)
		ca := &configv2.CertificateAuthority{
			Local: &configv2.CertificateAuthorityLocal{
				PrivateKey: caPrivateKey,
			},
			Certificate: caCert,
		}
		serial, err := cert.NewSerialNumber()
		require.NoError(t, err)
		_, clientCert, err := cert.CreateNewCertificateForClient(pkix.Name{CommonName: slackCommonName}, serial, "ecdsa", 224, "", ca)
		require.NoError(t, err)

		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://slack.example.com/command", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
		p.ServeSlackWebHook(context.Background(), recoder, req)

		res := recoder.Result()
		// BadGateway is a normal status in test because backend not found.
		assert.Equal(t, http.StatusBadGateway, res.StatusCode)
	})
}
