package scenario

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"go.f110.dev/heimdallr/e2e/framework"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/config/userconfig"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/session"
)

func TestL7ReverseProxy(t *testing.T) {
	f := framework.New(t)
	defer f.Execute()

	f.Describe("L7 Reverse Proxy", func(s *framework.Scenario) {
		s.BeforeEach(func(m *framework.Matcher) bool { return m.Must(f.Proxy.Reload()) })
		s.Defer(func() { f.Proxy.Cleanup() })

		s.Context("authorization flow", func(s *framework.Scenario) {
			s.BeforeAll(func(m *framework.Matcher) bool {
				f.Proxy.Backend(&configv2.Backend{Name: "test", Permissions: []*configv2.Permission{{Name: "all", Locations: []configv2.Location{{Any: "/"}}}}})
				f.Proxy.Role(&configv2.Role{Name: "test", Bindings: []*configv2.Binding{{Backend: "test", Permission: "all"}}})
				f.Proxy.User(&database.User{Id: "test@f110.dev", Roles: []string{"test"}})
				return true
			})
			s.AfterAll(func(m *framework.Matcher) bool { return f.Proxy.ClearConf() })

			s.Step("request backend url", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) bool {
					return f.Agents.User("test@f110.dev").Get(m, f.Proxy.URL("test"))
				})

				s.It("should redirect to entry point", func(m *framework.Matcher) bool {
					m.StatusCode(http.StatusSeeOther)
					u, err := m.LastResponse().Location()
					m.NoError(err)
					return m.Contains(u.String(), f.Proxy.URL("", "/auth"))
				})
			})

			s.Step("enter authorization flow", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) bool {
					m.Must(f.Agents.User("test@f110.dev").FollowRedirect(m))
					f.Agents.User("test@f110.dev").SaveCookie()
					return true
				})

				s.It("should redirect to OpenID Connect auth endpoint", func(m *framework.Matcher) bool {
					m.StatusCode(http.StatusFound)
					u, err := m.LastResponse().Location()
					m.NoError(err)
					return m.Contains(u.String(), "custom-idp/auth")
				})

				s.It("receive the cookie", func(m *framework.Matcher) bool {
					cookie := m.LastResponse().FindCookie(session.CookieName)
					m.NotNil(cookie)
					m.Equal(f.Proxy.DomainHost, cookie.Domain)
					m.True(cookie.HttpOnly)
					m.True(cookie.Secure)
					sess, err := f.Agents.DecodeCookieValue(cookie.Name, cookie.Value)
					m.NoError(err)
					m.Empty(sess.Id)
					return m.NotEmpty(sess.Unique)
				})
			})

			s.Step("show authorization view of identity provider", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) bool {
					return m.Must(f.Agents.User("test@f110.dev").FollowRedirect(m))
				})

				s.It("should get a page", func(m *framework.Matcher) bool {
					return m.StatusCode(http.StatusOK)
				})
			})

			s.Step("login identity provider", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) bool {
					agent := f.Agents.User("test@f110.dev")
					authResponse := &framework.AuthResponse{}
					m.Must(agent.ParseLastResponseBody(authResponse))
					return agent.Post(m, authResponse.LoginURL, fmt.Sprintf(`{"id":"test@f110.dev","query":"%s"}`, authResponse.Query))
				})

				s.It("should redirect to callback", func(m *framework.Matcher) bool {
					m.StatusCode(http.StatusFound)
					u, err := m.LastResponse().Location()
					m.NoError(err)
					return m.Contains(u.String(), "auth/callback")
				})
			})

			s.Step("follow redirect", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) bool {
					return m.Must(f.Agents.User("test@f110.dev").FollowRedirect(m))
				})

				s.It("should redirect to backend", func(m *framework.Matcher) bool {
					m.StatusCode(http.StatusFound)
					u, err := m.LastResponse().Location()
					m.NoError(err)
					return m.Equal(f.Proxy.URL("test"), u.String())
				})
			})
		})

		s.Context("access to the unknown backend", func(s *framework.Scenario) {
			s.Context("by authenticated user", func(s *framework.Scenario) {
				s.BeforeAll(func(m *framework.Matcher) bool {
					f.Proxy.Backend(&configv2.Backend{Name: "test", Permissions: []*configv2.Permission{{Name: "all", Locations: []configv2.Location{{Any: "/"}}}}})
					f.Proxy.Role(&configv2.Role{Name: "test", Bindings: []*configv2.Binding{{Backend: "test", Permission: "all"}}})
					f.Proxy.User(&database.User{Id: "test@f110.dev", Roles: []string{"test"}})
					return true
				})
				s.AfterAll(func(m *framework.Matcher) bool { return f.Proxy.ClearConf() })

				s.It("should close connection", func(m *framework.Matcher) bool {
					return f.Agents.Authorized("test@f110.dev").Get(m, f.Proxy.URL("unknown"))
				})
			})

			s.Context("by unauthenticated agent", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) bool {
					return f.Agents.Unauthorized().Get(m, f.Proxy.URL("unknown"))
				})

				s.It("should close connection", func(m *framework.Matcher) bool {
					return m.ResetConnection()
				})
			})
		})

		s.Context("access to the backend", func(s *framework.Scenario) {
			s.BeforeAll(func(m *framework.Matcher) bool {
				f.Proxy.Backend(&configv2.Backend{
					Name: "test1",
					HTTP: []*configv2.HTTPBackend{{Path: "/"}},
					Permissions: []*configv2.Permission{
						{Name: "all", Locations: []configv2.Location{{Any: "/"}}},
					},
				})
				f.Proxy.Role(&configv2.Role{Name: "test", Bindings: []*configv2.Binding{{Backend: "test1", Permission: "all"}}})
				f.Proxy.Role(&configv2.Role{Name: "test2"})
				f.Proxy.User(&database.User{Id: "test1@f110.dev", Roles: []string{"test"}})
				f.Proxy.User(&database.User{Id: "test2@f110.dev", Roles: []string{"test2"}})
				return true
			})
			s.AfterAll(func(m *framework.Matcher) bool { return f.Proxy.ClearConf() })

			s.Context("by unauthenticated agent", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) bool {
					return f.Agents.Unauthorized().Get(m, f.Proxy.URL("test1"))
				})

				s.It("should redirect to IdP", func(m *framework.Matcher) bool {
					m.StatusCode(http.StatusSeeOther)
					u, err := m.LastResponse().Location()
					m.NoError(err)
					return m.Equal(f.Proxy.URL("test1"), u.Query().Get("from"))
				})
			})

			s.Context("by authenticated user", func(s *framework.Scenario) {
				s.Context("who allowed an access", func(s *framework.Scenario) {
					s.Subject(func(m *framework.Matcher) bool {
						return f.Agents.Authorized("test1@f110.dev").Get(m, f.Proxy.URL("test1", "index.html"))
					})

					s.It("should proxy to backend", func(m *framework.Matcher) bool {
						return m.Equal(http.StatusBadGateway, m.LastResponse().StatusCode, "returns status 502 (BadGateway) because the upstream is down")
					})
				})

				s.Context("who not allowed an access", func(s *framework.Scenario) {
					s.Subject(func(m *framework.Matcher) bool {
						return f.Agents.Authorized("test2@f110.dev").Get(m, f.Proxy.URL("test1"))
					})

					s.It("should not proxy to the backend", func(m *framework.Matcher) bool {
						return m.Equal(http.StatusUnauthorized, m.LastResponse().StatusCode)
					})
				})
			})
		})

		s.Context("access to the backend which via connector", func(s *framework.Scenario) {
			var api1, api2 *framework.MockServer
			s.BeforeAll(func(m *framework.Matcher) bool {
				api1 = f.Proxy.MockServer(m, "api1")
				api2 = f.Proxy.MockServer(m, "api2")
				f.Proxy.Backend(&configv2.Backend{
					Name: "test",
					HTTP: []*configv2.HTTPBackend{
						{Path: "/api1", Agent: true},
						{Path: "/api2", Agent: true},
					},
					Permissions: []*configv2.Permission{
						{Name: "all", Locations: []configv2.Location{{Any: "/"}}},
					},
				})
				f.Proxy.Connector("test/api1", api1)
				f.Proxy.Connector("test/api2", api2)
				f.Proxy.Role(&configv2.Role{Name: "test", Bindings: []*configv2.Binding{{Backend: "test", Permission: "all"}}})
				f.Proxy.User(&database.User{Id: "test3@f110.dev", Roles: []string{"test"}})
				return true
			})
			s.AfterAll(func(m *framework.Matcher) bool { return f.Proxy.ClearConf() })

			s.Context("by authenticated user", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) bool {
					return f.Agents.Authorized("test3@f110.dev").Get(m, f.Proxy.URL("test", "/api1"))
				})

				s.It("should proxy to backend", func(m *framework.Matcher) bool {
					m.Equal(http.StatusOK, m.LastResponse().StatusCode)
					m.Len(api1.Requests(), 1)
					return m.Len(api2.Requests(), 0)
				})
			})
		})
	})
}

func TestL4Proxy(t *testing.T) {
	f := framework.New(t)
	defer f.Execute()

	f.Describe("L4 Proxy", func(s *framework.Scenario) {
		s.BeforeEach(func(m *framework.Matcher) bool { return m.Must(f.Proxy.Reload()) })
		s.Defer(func() { f.Proxy.Cleanup() })

		s.Context("user accesses to backend", func(s *framework.Scenario) {
			var tunnel *framework.Tunnel
			s.BeforeAll(func(m *framework.Matcher) bool {
				socket := f.Proxy.MockTCPServer(m, "socket1")
				f.Proxy.Backend(&configv2.Backend{
					Name: "test",
					Socket: &configv2.SocketBackend{
						Upstream: fmt.Sprintf("tcp://:%d", socket.Port),
					},
				})
				f.Proxy.RPCPermission(&configv2.RPCPermission{
					Name:  "test",
					Allow: []string{"proxy.rpc.certificateauthority.*"},
				})
				f.Proxy.Role(&configv2.Role{
					Name: "test",
					Bindings: []*configv2.Binding{
						{RPC: "test"},
						{Backend: "test"},
						{Backend: "dashboard", Permission: "all"},
					},
				})
				f.Proxy.User(&database.User{Id: "test@f110.dev", Roles: []string{"test"}})
				return true
			})
			s.AfterAll(func(m *framework.Matcher) bool {
				tunnel.Stop()
				return f.Proxy.ClearConf()
			})

			s.Step("init user env", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) bool {
					tunnel = f.Agents.Authorized("test@f110.dev").Tunnel(m)
					return tunnel.Init()
				})

				s.It("should create new private key", func(m *framework.Matcher) bool {
					return m.FileExists(filepath.Join(tunnel.Homedir, userconfig.Directory, userconfig.PrivateKeyFilename))
				})

				s.It("should create CSR file", func(m *framework.Matcher) bool {
					return m.FileExists(filepath.Join(tunnel.Homedir, userconfig.Directory, userconfig.CSRFilename))
				})
			})

			s.Step("send CSR to the dashboard", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) bool {
					v := url.Values{}
					v.Set("csr", tunnel.CSR(m))
					return f.Agents.Authorized("test@f110.dev").Post(m, f.Proxy.URL("dashboard", "/me/device/new"), v.Encode())
				})

				s.It("should success", func(m *framework.Matcher) bool {
					return m.StatusCode(http.StatusFound)
				})
			})

			s.Step("import the certificate", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) bool {
					return tunnel.LoadCert(tunnel.GetFirstCertificate(m, f.Agents.RPCClient("test@f110.dev")))
				})

				s.It("should create the certificate file", func(m *framework.Matcher) bool {
					return m.FileExists(filepath.Join(tunnel.Homedir, userconfig.Directory, userconfig.CertificateFilename))
				})
			})

			s.Step("open URL for authenticate", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) bool {
					return tunnel.Proxy(m, f.Proxy.Host("test"), f.DNS.Addr, bytes.NewReader([]byte("body")))
				})

				s.It("open URL", func(m *framework.Matcher) bool {
					return m.OpenURL()
				})
			})

			s.Step("authorizing", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) bool {
					return f.Agents.Authorized("test@f110.dev").Get(m, tunnel.OpeningURL())
				})
				s.Defer(func() {
					f.Agents.Authorized("test@f110.dev").SaveCookie()
				})

				s.It("returns status OK", func(m *framework.Matcher) bool {
					return m.StatusCode(http.StatusOK)
				})
			})

			s.Step("authorized", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) bool {
					return f.Agents.Authorized("test@f110.dev").Get(m, f.Proxy.URL("", "/token/authorized"))
				})

				s.It("returns status Found", func(m *framework.Matcher) bool {
					return m.StatusCode(http.StatusFound)
				})
			})

			s.Step("follow redirect", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) bool {
					m.Must(f.Agents.Authorized("test@f110.dev").FollowRedirect(m))
					return tunnel.WaitGettingToken(time.Second)
				})

				s.It("pass the token to the local process", func(m *framework.Matcher) bool {
					return m.FileExists(filepath.Join(tunnel.Homedir, userconfig.Directory, userconfig.TokenFilename))
				})

				s.It("got bytes from TCP Server", func(m *framework.Matcher) bool {
					return m.Equal([]byte("HELLO"), tunnel.Buf.Bytes())
				})
			})
		})
	})
}
