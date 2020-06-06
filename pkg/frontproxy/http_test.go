package frontproxy

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

	"github.com/f110/lagrangian-proxy/pkg/auth"
	"github.com/f110/lagrangian-proxy/pkg/cert"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/database/memory"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc/rpcclient"
	"github.com/f110/lagrangian-proxy/pkg/session"
)

func newTLSConnectionState() *tls.ConnectionState {
	return &tls.ConnectionState{HandshakeComplete: true}
}

func TestNewHttpProxy(t *testing.T) {
	conf := &config.Config{
		Logger: &config.Logger{},
	}
	c := rpcclient.NewWithClient(nil, nil, nil)
	p := NewHttpProxy(conf, nil, c)

	if p == nil {
		t.Fatal("NewHttpProxy should return a value")
	}
}

func TestHttpProxy_ServeHTTP(t *testing.T) {
	u := memory.NewUserDatabase()
	_ = u.Set(nil, &database.User{Id: "foobarbaz@example.com", Roles: []string{"test", "unknown"}})
	backends := []*config.Backend{
		{
			Name: "test",
			Permissions: []*config.Permission{
				{Name: "all", Locations: []config.Location{{Get: "/"}}},
			},
		},
		{
			Name:        "webhook",
			WebHook:     "github",
			WebHookPath: []string{"/github"},
		},
		{
			Name:        "slack",
			WebHook:     "slack",
			WebHookPath: []string{"/command"},
		},
		{
			Name:      "http",
			AllowHttp: true,
			Permissions: []*config.Permission{
				{Name: "all", Locations: []config.Location{{Any: "/"}}},
			},
		},
	}
	roles := []*config.Role{
		{
			Name: "test",
			Bindings: []*config.Binding{
				{Backend: "test", Permission: "all"},
				{Backend: "http", Permission: "all"},
			},
		},
	}
	rpcPermissions := []*config.RpcPermission{}

	signReqKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signReqPubKey := signReqKey.PublicKey
	conf := &config.Config{
		General: &config.General{
			ServerNameHost:    "example.com",
			SigningPrivateKey: signReqKey,
			SigningPublicKey:  signReqPubKey,
		},
		Logger: &config.Logger{
			Level: "debug",
		},
		FrontendProxy: &config.FrontendProxy{
			GithubWebhookSecret: []byte("test"),
		},
	}
	s := session.NewSecureCookieStore([]byte("test"), []byte("testtesttesttesttesttesttesttest"), "example.com")
	if err := conf.General.Load(backends, roles, rpcPermissions); err != nil {
		t.Fatal(err)
	}
	auth.Init(conf, s, u, nil, nil)
	if err := logger.Init(conf.Logger); err != nil {
		t.Fatal(err)
	}

	c := rpcclient.NewWithClient(nil, nil, nil)
	p := NewHttpProxy(conf, nil, c)

	t.Run("Session not found", func(t *testing.T) {
		t.Parallel()

		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://test.example.com", nil)
		req.TLS = newTLSConnectionState()
		p.ServeHTTP(context.Background(), recorder, req)

		res := recorder.Result()
		if res.StatusCode != http.StatusSeeOther {
			t.Fatalf("expect StatusSeeOther: %s", res.Status)
		}
	})

	t.Run("User not found", func(t *testing.T) {
		t.Parallel()

		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://test.example.com", nil)
		req.TLS = newTLSConnectionState()
		cookie, err := s.Cookie(session.New("foobar@example.com"))
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(cookie)
		p.ServeHTTP(context.Background(), recoder, req)

		res := recoder.Result()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expect StatusUnauthorized: %s", res.Status)
		}
	})

	t.Run("Host not found", func(t *testing.T) {
		t.Parallel()

		defer func() {
			err := recover()
			if err == nil {
				t.Fatal("ServeHTTP should panic but not")
			}
			if err != http.ErrAbortHandler {
				t.Fatalf("expect http.ErrAbortHandler: %v", err)
			}
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
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(cookie)
		p.ServeHTTP(context.Background(), recoder, req)

		res := recoder.Result()
		if res.StatusCode != http.StatusBadGateway {
			t.Fatalf("expect StatusBadGateway: %s", res.Status)
		}
	})

	t.Run("Success via http", func(t *testing.T) {
		t.Parallel()

		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://http.example.com/", nil)
		cookie, err := s.Cookie(session.New("foobarbaz@example.com"))
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(cookie)
		p.ServeHTTP(context.Background(), recoder, req)

		res := recoder.Result()
		if res.StatusCode != http.StatusBadGateway {
			t.Fatalf("expect StatusBadGateway: %s", res.Status)
		}
	})

	t.Run("Backend is not allowed http access", func(t *testing.T) {
		t.Parallel()

		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://test.example.com/", nil)
		cookie, err := s.Cookie(session.New("foobarbaz@example.com"))
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(cookie)
		p.ServeHTTP(context.Background(), recoder, req)

		res := recoder.Result()
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("expect StatusUpgradeRequired: %s", res.Status)
		}
	})

	t.Run("Webhook from github without signature", func(t *testing.T) {
		t.Parallel()

		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://webhook.example.com/github", nil)
		p.ServeGithubWebHook(context.Background(), recoder, req)

		res := recoder.Result()
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("expect StatusBadRequest: %s", res.Status)
		}
	})

	t.Run("Webhook from github with valid signature", func(t *testing.T) {
		t.Parallel()

		body := strings.NewReader("{}")
		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://webhook.example.com/github", body)
		// req.TLS = newTLSConnectionState()
		mac := hmac.New(sha1.New, conf.FrontendProxy.GithubWebhookSecret)
		mac.Write([]byte("{}"))
		sign := mac.Sum(nil)
		req.Header.Set("X-Hub-Signature", "sha1="+hex.EncodeToString(sign))
		p.ServeGithubWebHook(context.Background(), recoder, req)

		res := recoder.Result()
		if res.StatusCode != http.StatusBadGateway {
			t.Fatalf("expect StatusBadGateway: %s", res.Status)
		}
	})

	t.Run("Webhook from slack without client certificate", func(t *testing.T) {
		t.Parallel()

		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://slack.example.com/command", nil)
		p.ServeSlackWebHook(context.Background(), recoder, req)

		res := recoder.Result()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expect StatusUnauthorized: %s", res.Status)
		}
	})

	t.Run("Webhook from slack with invalid client certificate", func(t *testing.T) {
		t.Parallel()

		caCert, caPrivateKey, err := cert.CreateCertificateAuthority("test", "", "", "jp")
		if err != nil {
			t.Fatal(err)
		}
		ca := &config.CertificateAuthority{
			Certificate: caCert,
			PrivateKey:  caPrivateKey,
		}
		serial, err := cert.NewSerialNumber()
		if err != nil {
			t.Fatal(err)
		}
		_, clientCert, err := cert.CreateNewCertificateForClient(pkix.Name{CommonName: "slack.f110.dev"}, serial, "ecdsa", 224, "", ca)
		if err != nil {
			t.Fatal()
		}

		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://slack.example.com/command", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
		p.ServeSlackWebHook(context.Background(), recoder, req)

		res := recoder.Result()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expect StatusBadGateway: %s", res.Status)
		}
	})

	t.Run("Webhook from slack with client certificate", func(t *testing.T) {
		t.Parallel()

		caCert, caPrivateKey, err := cert.CreateCertificateAuthority("test", "", "", "jp")
		if err != nil {
			t.Fatal(err)
		}
		ca := &config.CertificateAuthority{
			Certificate: caCert,
			PrivateKey:  caPrivateKey,
		}
		serial, err := cert.NewSerialNumber()
		if err != nil {
			t.Fatal(err)
		}
		_, clientCert, err := cert.CreateNewCertificateForClient(pkix.Name{CommonName: slackCommonName}, serial, "ecdsa", 224, "", ca)
		if err != nil {
			t.Fatal()
		}

		recoder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://slack.example.com/command", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCert}}
		p.ServeSlackWebHook(context.Background(), recoder, req)

		res := recoder.Result()
		// BadGateway is a normal status in test due to backend not found.
		if res.StatusCode != http.StatusBadGateway {
			t.Fatalf("expect StatusBadGateway: %s", res.Status)
		}
	})
}
