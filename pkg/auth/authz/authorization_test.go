package authz

import (
	"context"
	"crypto"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/session"
)

const (
	serverName = "proxy.example.com"
)

var (
	caCert       *x509.Certificate
	caPrivateKey crypto.PrivateKey
	certPool     *x509.CertPool
)

func init() {
	c, p, err := cert.CreateCertificateAuthority("for test", "test", "", "jp")
	if err != nil {
		panic(err)
	}
	caCert = c
	caPrivateKey = p
	cp := x509.NewCertPool()
	cp.AddCert(caCert)
	certPool = cp
}

func TestAuthorization(t *testing.T) {
	t.Run("DisableAuthentication", func(t *testing.T) {
		t.Parallel()

		t.Run("Any path", func(t *testing.T) {
			t.Parallel()

			backend := &configv2.Backend{
				Name:         "public",
				DisableAuthn: true,
			}

			a := newAuthorization(t, backend, &configv2.Role{})
			req := httptest.NewRequest(http.MethodGet, "http://public.proxy.example.com/ok", nil)
			err := a.Authorization(context.TODO(), req, nil, nil)
			require.NoError(t, err)
		})

		t.Run("Subset of path", func(t *testing.T) {
			t.Parallel()

			backend := &configv2.Backend{
				Name:         "public-path",
				DisableAuthn: true,
				Permissions: []*configv2.Permission{
					{Name: "ok", Locations: []configv2.Location{{Get: "/ok"}}},
				},
			}

			cases := []struct {
				Path      string
				ExpectErr error
			}{
				{Path: "/ok", ExpectErr: nil},
				{Path: "/notallow", ExpectErr: ErrNotAllowed},
			}

			for _, c := range cases {
				c := c
				t.Run("", func(t *testing.T) {
					t.Parallel()

					a := newAuthorization(t, backend, &configv2.Role{})
					req := httptest.NewRequest(http.MethodGet, "http://"+backend.Name+"."+serverName+c.Path, nil)
					err := a.Authorization(context.TODO(), req, nil, nil)
					if c.ExpectErr == nil {
						require.NoError(t, err)
					} else {
						require.Error(t, err)
						require.Equal(t, c.ExpectErr, err)
					}
				})
			}
		})
	})

	t.Run("RequireAuthzBackend", func(t *testing.T) {
		t.Parallel()

		t.Run("Normal", func(t *testing.T) {
			t.Parallel()

			backend := &configv2.Backend{
				Name: "test",
				Permissions: []*configv2.Permission{
					{Name: "ok", Locations: []configv2.Location{{Get: "/ok"}}},
				},
			}
			role := &configv2.Role{
				Name: "test",
				Bindings: []*configv2.Binding{
					{Backend: "test", Permission: "ok"},
				},
			}
			user := &database.User{Id: "foobar@example.com", Roles: []string{"test"}}

			a := newAuthorization(t, backend, role)
			req := httptest.NewRequest(http.MethodGet, "http://"+backend.Name+"."+serverName+"/ok", nil)
			err := a.Authorization(context.TODO(), req, user, nil)
			require.NoError(t, err)
		})

		t.Run("Secure backend", func(t *testing.T) {
			t.Parallel()

			backend := &configv2.Backend{
				Name: "topsecret",
				Permissions: []*configv2.Permission{
					{Name: "ok", Locations: []configv2.Location{{Get: "/ok"}}},
				},
				MaxSessionDuration: &configv2.Duration{Duration: 1 * time.Minute},
			}
			role := &configv2.Role{
				Name: "test",
				Bindings: []*configv2.Binding{
					{Backend: "topsecret", Permission: "ok"},
				},
			}
			user := &database.User{Id: "foobar@example.com", Roles: []string{"test"}}

			cases := []struct {
				Session   *session.Session
				ExpectErr error
			}{
				{Session: nil, ExpectErr: ErrSessionNotFound},
				{Session: &session.Session{IssuedAt: time.Now().Add(-30 * time.Second)}},
				{Session: &session.Session{IssuedAt: time.Now().Add(-2 * time.Minute)}, ExpectErr: ErrSessionNotFound},
			}

			for _, c := range cases {
				c := c
				t.Run("", func(t *testing.T) {
					t.Parallel()

					a := newAuthorization(t, backend, role)
					req := httptest.NewRequest(http.MethodGet, "http://"+backend.Name+"."+serverName+"/ok", nil)
					err := a.Authorization(context.TODO(), req, user, c.Session)
					if c.ExpectErr != nil {
						require.Error(t, err, "expected to occurred error")
						require.Equal(t, c.ExpectErr, err, "expected %v", c.ExpectErr)
					} else {
						require.NoError(t, err)
					}
				})
			}
		})
	})
}

func TestAuthorizationSocket(t *testing.T) {
	t.Run("Not allowed", func(t *testing.T) {
		t.Parallel()

		backend := &configv2.Backend{
			Name: "test",
			Permissions: []*configv2.Permission{
				{Name: "ok", Locations: []configv2.Location{{Get: "/ok"}}},
			},
		}
		user := &database.User{Id: "foobar@example.com", Roles: []string{"test"}}

		a := newAuthorization(t, backend, &configv2.Role{Name: "test", Bindings: []*configv2.Binding{}})
		err := a.AuthorizationSocket(context.Background(), backend, user)
		require.Error(t, err, "Expected to occurred error")
		require.Equal(t, ErrNotAllowed, err)
	})

	t.Run("Allow", func(t *testing.T) {
		t.Parallel()

		backend := &configv2.Backend{
			Name: "test",
			Permissions: []*configv2.Permission{
				{Name: "ok", Locations: []configv2.Location{{Get: "/ok"}}},
			},
		}
		role := &configv2.Role{
			Name: "test",
			Bindings: []*configv2.Binding{
				{Backend: "test", Permission: "ok"},
			},
		}
		user := &database.User{Id: "foobar@example.com", Roles: []string{"unknown", "test"}}

		a := newAuthorization(t, backend, role)
		err := a.AuthorizationSocket(context.Background(), backend, user)
		require.NoError(t, err)
	})
}

func newAuthorization(t *testing.T, backend *configv2.Backend, role *configv2.Role) *authorization {
	assert.NotNil(t, backend)
	assert.NotNil(t, role)

	a := &authorization{
		Config: &configv2.Config{
			AccessProxy: &configv2.AccessProxy{
				ServerNameHost: serverName,
				Backends:       []*configv2.Backend{backend},
			},
			AuthorizationEngine: &configv2.AuthorizationEngine{
				RootUsers: []string{"root@example.com"},
				Roles:     []*configv2.Role{role},
			},
			CertificateAuthority: &configv2.CertificateAuthority{
				Local: &configv2.CertificateAuthorityLocal{
					Certificate: caCert,
					PrivateKey:  caPrivateKey,
					CertPool:    certPool,
				},
			},
		},
	}
	err := a.Config.AccessProxy.Setup(a.Config.AccessProxy.Backends)
	if err != nil {
		t.Fatal(err)
	}
	err = a.Config.AuthorizationEngine.Setup(a.Config.AuthorizationEngine.Roles, []*configv2.RPCPermission{})
	if err != nil {
		t.Fatal(err)
	}

	return a
}
