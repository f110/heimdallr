package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/f110/lagrangian-proxy/pkg/cert"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/database/memory"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc/rpcclient"
	"github.com/f110/lagrangian-proxy/pkg/session"
)

type testRevokedCertClient struct {
	revokedCert []*rpcclient.RevokedCert
}

func NewRevokedCertClient() *testRevokedCertClient {
	return &testRevokedCertClient{revokedCert: make([]*rpcclient.RevokedCert, 0)}
}

func (r *testRevokedCertClient) Get() []*rpcclient.RevokedCert {
	return r.revokedCert
}

func TestAuthenticator_Authenticate(t *testing.T) {
	s := session.NewSecureCookieStore([]byte("test"), []byte("testtesttesttesttesttesttesttest"), "example.com")
	u := memory.NewUserDatabase()
	rc := &testRevokedCertClient{}
	caCertBytes, caPrivateKey, err := cert.CreateCertificateAuthority("for test", "test", "", "jp")
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		t.Fatal(err)
	}
	cp := x509.NewCertPool()
	cp.AddCert(caCert)
	a := &authenticator{
		Config: &config.General{
			ServerNameHost: "proxy.example.com",
			RootUsers:      []string{"root@example.com"},
			Backends: []*config.Backend{
				{
					Name: "test",
					Permissions: []*config.Permission{
						{Name: "ok", Locations: []config.Location{{Get: "/ok"}}},
						{Name: "ok_but_nobind", Locations: []config.Location{{Get: "/no_bind"}}},
					},
				},
				{
					Name:            "root",
					AllowAsRootUser: true,
					Permissions: []*config.Permission{
						{Name: "ok", Locations: []config.Location{{Get: "/ok"}}},
					},
				},
			},
			Roles: []*config.Role{
				{Name: "test", Bindings: []*config.Binding{
					{Backend: "test", Permission: "ok"},
				}},
			},
			CertificateAuthority: &config.CertificateAuthority{
				Certificate: caCert,
				PrivateKey:  caPrivateKey,
				CertPool:    cp,
			},
		},
		sessionStore: s,
		userDatabase: u,
		revokedCert:  rc,
	}
	err = a.Config.Load(a.Config.Backends, a.Config.Roles, []*config.RpcPermission{})
	if err != nil {
		t.Fatal(err)
	}
	_ = u.Set(nil, &database.User{Id: "foobar@example.com", Roles: []string{"test", "unknown"}})
	logger.Init(&config.Logger{Level: "debug"})

	t.Run("Cookie", func(t *testing.T) {
		t.Parallel()

		t.Run("normal", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)
			c, err := s.Cookie(session.New("foobar@example.com"))
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(c)
			user, err := a.Authenticate(req)
			if err != nil {
				t.Fatal(err)
			}
			if user.Id != "foobar@example.com" {
				t.Errorf("expect foobar@example.com: %s", user.Id)
			}
		})

		t.Run("normal with root user", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://root.proxy.example.com/ok", nil)
			c, err := s.Cookie(session.New("root@example.com"))
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(c)
			user, err := a.Authenticate(req)
			if err != nil {
				t.Fatal(err)
			}
			if user.Id != "root@example.com" {
				t.Errorf("expect foobar@example.com: %s", user.Id)
			}
			if !user.RootUser {
				t.Error("expect root@example.com is root")
			}
		})

		t.Run("not have cookie", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)

			_, err := a.Authenticate(req)
			if err != ErrSessionNotFound {
				t.Errorf("expect session not found: %v", err)
			}
		})

		t.Run("user not found", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)
			c, err := s.Cookie(session.New("foo@example.com"))
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(c)
			_, err = a.Authenticate(req)
			if err != ErrUserNotFound {
				t.Errorf("expect user not found: %v", err)
			}
		})

		t.Run("unknown host", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://unknownhost.example.com/ok", nil)

			_, err := a.Authenticate(req)
			if err != ErrHostnameNotFound {
				t.Errorf("expect hostname not found: %v", err)
			}
		})

		t.Run("not allowed path", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/no_good", nil)
			c, err := s.Cookie(session.New("foobar@example.com"))
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(c)
			_, err = a.Authenticate(req)
			if err != ErrNotAllowed {
				t.Errorf("expect not allowed: %v", err)
			}
		})

		t.Run("role not have clearance", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/no_bind", nil)
			c, err := s.Cookie(session.New("foobar@example.com"))
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(c)
			_, err = a.Authenticate(req)
			if err != ErrNotAllowed {
				t.Errorf("expect not allowed: %v", err)
			}
		})
	})

	t.Run("client certificate auth", func(t *testing.T) {
		t.Parallel()

		t.Run("normal", func(t *testing.T) {
			t.Parallel()

			subject := pkix.Name{CommonName: "foobar@example.com"}
			pemEncodedCSRBytes, _, err := cert.CreateCertificateRequest(subject, []string{})
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(pemEncodedCSRBytes)
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			clientCert, err := cert.SigningCertificateRequest(csr, a.Config.CertificateAuthority)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)
			req.TLS = &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{clientCert},
			}
			user, err := a.Authenticate(req)
			if err != nil {
				t.Fatal(err)
			}
			if user.Id != "foobar@example.com" {
				t.Errorf("expect foobar@example.com: %s", user.Id)
			}
		})

		t.Run("normal via client certificate auth", func(t *testing.T) {
			t.Parallel()

			subject := pkix.Name{CommonName: "foobar@example.com"}
			pemEncodedCSRBytes, _, err := cert.CreateCertificateRequest(subject, []string{})
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(pemEncodedCSRBytes)
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			clientCert, err := cert.SigningCertificateRequest(csr, a.Config.CertificateAuthority)
			if err != nil {
				t.Fatal(err)
			}
			rc.revokedCert = append(rc.revokedCert, &rpcclient.RevokedCert{SerialNumber: clientCert.SerialNumber})
			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)
			req.TLS = &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{clientCert},
			}
			_, err = a.Authenticate(req)
			if err == nil {
				t.Fatal("expected to occurred error but not")
			}
			if err != ErrInvalidCertificate {
				t.Fatalf("expected ErrInvalidCertificate: %v", err)
			}
		})
	})

	t.Run("Authorization header", func(t *testing.T) {
		t.Parallel()

		t.Run("normal", func(t *testing.T) {
			t.Parallel()

			err := u.SetAccessToken(context.Background(), &database.AccessToken{Value: t.Name(), UserId: "foobar@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)
			req.Header.Set("Authorization", "LP-TOKEN")
			req.Header.Set("X-LP-TOKEN", t.Name())
			user, err := a.Authenticate(req)
			if err != nil {
				t.Fatal(err)
			}
			if user.Id != "foobar@example.com" {
				t.Errorf("expect foobar@example.com: %s", user.Id)
			}
		})

		t.Run("header not found", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)
			req.Header.Set("Authorization", "LP-TOKEN")
			_, err = a.Authenticate(req)
			if err == nil {
				t.Fatal("expected to occurred error but not")
			}
			if err != ErrUserNotFound {
				t.Fatalf("expected ErrUserNotFound: %v", err)
			}
		})

		t.Run("invalid token", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)
			req.Header.Set("Authorization", "LP-TOKEN")
			req.Header.Set("X-LP-Token", "unknown-token")
			_, err = a.Authenticate(req)
			if err == nil {
				t.Fatal("expected to occurred error but not")
			}
			if err != ErrUserNotFound {
				t.Fatalf("expected ErrUserNotFound: %v", err)
			}
		})

		t.Run("user not found", func(t *testing.T) {
			t.Parallel()

			err := u.SetAccessToken(context.Background(), &database.AccessToken{Value: "dummy-token", UserId: "piyo@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)
			req.Header.Set("Authorization", "LP-TOKEN")
			req.Header.Set("X-LP-TOKEN", "dummy-token")
			_, err = a.Authenticate(req)
			if err == nil {
				t.Fatal("expected to occurred error but not")
			}
			if err != ErrUserNotFound {
				t.Fatalf("expected ErrUserNotFound: %v", err)
			}
		})
	})
}

func TestAuthenticator_AuthenticateForSocket(t *testing.T) {
	s := session.NewSecureCookieStore([]byte("test"), []byte("testtesttesttesttesttesttesttest"), "example.com")
	u := memory.NewUserDatabase()
	token := memory.NewTokenDatabase()
	a := &authenticator{
		Config: &config.General{
			ServerNameHost: "proxy.example.com",
			Backends: []*config.Backend{
				{
					Name:   "test",
					Socket: true,
					Permissions: []*config.Permission{
						{Name: "ok", Locations: []config.Location{{Get: "/ok"}}},
						{Name: "ok_but_nobind", Locations: []config.Location{{Get: "/no_bind"}}},
					},
				},
			},
			Roles: []*config.Role{
				{
					Name: "test",
					Bindings: []*config.Binding{
						{Backend: "test"},
					},
				},
			},
		},
		sessionStore:  s,
		userDatabase:  u,
		tokenDatabase: token,
	}
	err := a.Config.Load(a.Config.Backends, a.Config.Roles, []*config.RpcPermission{})
	if err != nil {
		t.Fatal(err)
	}
	_ = u.Set(nil, &database.User{Id: "foobar@example.com", Roles: []string{"test", "unknown"}})
	_ = u.Set(nil, &database.User{Id: "piyo@example.com", Roles: []string{}})

	t.Run("empty token", func(t *testing.T) {
		t.Parallel()

		_, err := a.AuthenticateForSocket(context.Background(), "", "")
		if err == nil {
			t.Fatal("expected to occurred error but not")
		}
		if err != ErrInvalidToken {
			t.Fatalf("expected ErrInvalidToken: %v", err)
		}
	})

	t.Run("empty host", func(t *testing.T) {
		t.Parallel()

		_, err := a.AuthenticateForSocket(context.Background(), "dummy", "")
		if err == nil {
			t.Fatal("expected to occurred error but not")
		}
		if err != ErrHostnameNotFound {
			t.Fatalf("expected ErrHostnameNotFound: %v", err)
		}
	})

	t.Run("unknown host", func(t *testing.T) {
		t.Parallel()

		_, err := a.AuthenticateForSocket(context.Background(), "dummy", "unknown")
		if err == nil {
			t.Fatal("expected to occurred error but not")
		}
		if err != ErrHostnameNotFound {
			t.Fatalf("expected ErrHostnameNotFound: %v", err)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		t.Parallel()

		_, err := a.AuthenticateForSocket(context.Background(), "dummy", "test.proxy.example.com")
		if err == nil {
			t.Fatal("expected to occurred error but not")
		}
		if err != ErrInvalidToken {
			t.Fatalf("expected ErrInvalidToken: %v", err)
		}
	})

	t.Run("unknown user", func(t *testing.T) {
		t.Parallel()

		newToken, err := token.IssueToken(context.Background(), "", "")
		if err != nil {
			t.Fatal(err)
		}
		_, err = a.AuthenticateForSocket(context.Background(), newToken.Token, "test.proxy.example.com")
		if err == nil {
			t.Fatal("expected to occurred error but not")
		}
		if err != ErrUserNotFound {
			t.Fatalf("expected ErrUserNotFound: %v", err)
		}
	})

	t.Run("user not allowed", func(t *testing.T) {
		t.Parallel()

		newCode, err := token.NewCode(context.Background(), "piyo@example.com", "", "")
		if err != nil {
			t.Fatal(err)
		}
		newToken, err := token.IssueToken(context.Background(), newCode.Code, "")
		if err != nil {
			t.Fatal(err)
		}
		_, err = a.AuthenticateForSocket(context.Background(), newToken.Token, "test.proxy.example.com")
		if err == nil {
			t.Fatal("expected to occurred error but not")
		}
		if err != ErrNotAllowed {
			t.Fatalf("expected ErrNotAllowed: %v", err)
		}
	})

	t.Run("allow", func(t *testing.T) {
		t.Parallel()

		newCode, err := token.NewCode(context.Background(), "foobar@example.com", "", "")
		if err != nil {
			t.Fatal(err)
		}
		newToken, err := token.IssueToken(context.Background(), newCode.Code, "")
		if err != nil {
			t.Fatal(err)
		}
		user, err := a.AuthenticateForSocket(context.Background(), newToken.Token, "test.proxy.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if user.Id != "foobar@example.com" {
			t.Fatalf("AuthenticateForSocket returns user but is not expected: %v", user.Id)
		}
	})
}
