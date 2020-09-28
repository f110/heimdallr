package scenario

import (
	"fmt"
	"net/http"
	"testing"

	"go.f110.dev/heimdallr/e2e/framework"
	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/session"
)

func TestProxy(t *testing.T) {
	f := framework.New(t)
	defer f.Execute()

	f.Describe("L7 Reverse Proxy", func(s *framework.Scenario) {
		s.BeforeEach(func(m *framework.Matcher) { m.Must(f.Proxy.Reload()) })
		s.Defer(func() { f.Proxy.Cleanup() })

		s.Context("authorization flow", func(s *framework.Scenario) {
			s.BeforeAll(func(m *framework.Matcher) {
				f.Proxy.Backend(&config.Backend{Name: "test", Permissions: []*config.Permission{{Name: "all", Locations: []config.Location{{Any: "/"}}}}})
				f.Proxy.Role(&config.Role{Name: "test", Bindings: []*config.Binding{{Backend: "test", Permission: "all"}}})
				f.Proxy.User(&database.User{Id: "test@f110.dev", Roles: []string{"test"}})
			})

			s.Step("request backend url", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) {
					f.Agents.User("test@f110.dev").Get(m, f.Proxy.URL("test"))
				})

				s.It("should redirect to entry point", func(m *framework.Matcher) {
					m.StatusCode(http.StatusSeeOther)
					u, err := m.LastResponse().Location()
					m.NoError(err)
					m.Contains(u.String(), f.Proxy.URL("", "/auth"))
				})
			})

			s.Step("enter authorization flow", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) {
					m.Must(f.Agents.User("test@f110.dev").FollowRedirect(m))
					f.Agents.User("test@f110.dev").SaveCookie()
				})

				s.It("should redirect to OpenID Connect auth endpoint", func(m *framework.Matcher) {
					m.StatusCode(http.StatusFound)
					u, err := m.LastResponse().Location()
					m.NoError(err)
					m.Contains(u.String(), "custom-idp/auth")
				})

				s.It("receive the cookie", func(m *framework.Matcher) {
					cookie := m.LastResponse().FindCookie(session.CookieName)
					m.NotNil(cookie)
					m.Equal(f.Proxy.DomainHost, cookie.Domain)
					m.True(cookie.HttpOnly)
					m.True(cookie.Secure)
					sess, err := f.Agents.DecodeCookieValue(cookie.Name, cookie.Value)
					m.NoError(err)
					m.Empty(sess.Id)
					m.NotEmpty(sess.Unique)
				})
			})

			s.Step("show authorization view of identity provider", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) {
					m.Must(f.Agents.User("test@f110.dev").FollowRedirect(m))
				})

				s.It("should get a page", func(m *framework.Matcher) {
					m.StatusCode(http.StatusOK)
				})
			})

			s.Step("login identity provider", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) {
					agent := f.Agents.User("test@f110.dev")
					authResponse := &framework.AuthResponse{}
					m.Must(agent.ParseLastResponseBody(authResponse))
					agent.Post(m, authResponse.LoginURL, fmt.Sprintf(`{"id":"test@f110.dev","query":"%s"}`, authResponse.Query))
				})

				s.It("should success", func(m *framework.Matcher) {
					m.StatusCode(http.StatusFound)
				})
			})

			s.Step("follow redirect", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) {
					m.Must(f.Agents.User("test@f110.dev").FollowRedirect(m))
				})

				s.It("should success", func(m *framework.Matcher) {
					m.StatusCode(http.StatusFound)
					u, _ := m.LastResponse().Location()
					m.Equal(f.Proxy.URL("test"), u.String())
				})
			})
		})

		s.Context("access to the unknown backend", func(s *framework.Scenario) {
			s.Context("by authenticated user", func(s *framework.Scenario) {
				s.BeforeAll(func(m *framework.Matcher) {
					f.Proxy.Backend(&config.Backend{Name: "test", Permissions: []*config.Permission{{Name: "all", Locations: []config.Location{{Any: "/"}}}}})
					f.Proxy.Role(&config.Role{Name: "test", Bindings: []*config.Binding{{Backend: "test", Permission: "all"}}})
					f.Proxy.User(&database.User{Id: "test@f110.dev", Roles: []string{"test"}})
				})

				s.It("should close connection", func(m *framework.Matcher) {
					f.Agents.Authorized("test@f110.dev").Get(m, f.Proxy.URL("unknown"))
				})
			})

			s.Context("by unauthenticated agent", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) {
					f.Agents.Unauthorized().Get(m, f.Proxy.URL("unknown"))
				})

				s.It("should close connection", func(m *framework.Matcher) {
					m.ResetConnection()
				})
			})
		})

		s.Context("access to the backend", func(s *framework.Scenario) {
			s.BeforeAll(func(m *framework.Matcher) {
				f.Proxy.Backend(&config.Backend{Name: "test", Permissions: []*config.Permission{{Name: "all", Locations: []config.Location{{Any: "/"}}}}})
				f.Proxy.Role(&config.Role{Name: "test", Bindings: []*config.Binding{{Backend: "test", Permission: "all"}}})
				f.Proxy.Role(&config.Role{Name: "test2"})
				f.Proxy.User(&database.User{Id: "test@f110.dev", Roles: []string{"test"}})
				f.Proxy.User(&database.User{Id: "test2@f110.dev", Roles: []string{"test2"}})
			})

			s.Context("by unauthenticated agent", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) {
					f.Agents.Unauthorized().Get(m, f.Proxy.URL("test"))
				})

				s.It("should redirect to IdP", func(m *framework.Matcher) {
					m.StatusCode(http.StatusSeeOther)
					u, err := m.LastResponse().Location()
					m.NoError(err)
					m.Equal(f.Proxy.URL("test"), u.Query().Get("from"))
				})
			})

			s.Context("by authenticated user", func(s *framework.Scenario) {
				s.Context("who allowed an access", func(s *framework.Scenario) {
					s.Subject(func(m *framework.Matcher) {
						f.Agents.Authorized("test@f110.dev").Get(m, f.Proxy.URL("test", "index.html"))
					})

					s.It("should proxy to backend", func(m *framework.Matcher) {
						m.Equal(http.StatusBadGateway, m.LastResponse().StatusCode, "returns status 502 (BadGateway) because the upstream is down")
					})
				})

				s.Context("who not allowed an access", func(s *framework.Scenario) {
					s.Subject(func(m *framework.Matcher) {
						f.Agents.Authorized("test2@f110.dev").Get(m, f.Proxy.URL("test"))
					})

					s.It("should not proxy to the backend", func(m *framework.Matcher) {
						m.Equal(http.StatusUnauthorized, m.LastResponse().StatusCode)
					})
				})
			})
		})
	})
}
