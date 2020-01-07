package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/database/memory"
	"github.com/f110/lagrangian-proxy/pkg/session"
)

func TestAuthenticator_Authenticate(t *testing.T) {
	s := session.NewSecureCookieStore([]byte("test"), []byte("testtesttesttesttesttesttesttest"), "example.com")
	u := memory.NewUserDatabase()
	a := &authenticator{
		Config: &config.General{
			ServerNameHost: "proxy.example.com",
			Backends: []*config.Backend{
				{Name: "test", Permissions: []*config.Permission{
					{Name: "ok", Locations: []config.Location{{Get: "/ok"}}},
					{Name: "ok_but_nobind", Locations: []config.Location{{Get: "/no_bind"}}},
				}},
			},
			Roles: []*config.Role{
				{Name: "test", Bindings: []*config.Binding{
					{Backend: "test", Permission: "ok"},
				}},
			},
		},
		sessionStore: s,
		userDatabase: u,
	}
	err := a.Config.Load(a.Config.Backends, a.Config.Roles, []*config.RpcPermission{})
	if err != nil {
		t.Fatal(err)
	}
	_ = u.Set(nil, &database.User{Id: "foobar@example.com", Roles: []string{"test", "unknown"}})

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
}
