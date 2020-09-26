package scenario

import (
	"fmt"
	"net/http"
	"testing"

	"go.f110.dev/heimdallr/e2e/framework"
	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/database"
)

func TestProxy(t *testing.T) {
	f := framework.New(t)
	defer f.Execute()

	f.Describe("L7 Reverse Proxy", func(s *framework.Scenario) {
		s.BeforeEach(func(m *framework.Matcher) { m.Must(f.Proxy.Reload()) })
		s.Defer(func() { f.Proxy.Cleanup() })

		s.Context("access to the unknown backend", func(s *framework.Scenario) {
			s.Context("by authenticated user", func(s *framework.Scenario) {
				s.BeforeAll(func(m *framework.Matcher) {
					f.Proxy.Backend(&config.Backend{Name: "test", Permissions: []*config.Permission{{Name: "all", Locations: []config.Location{{Any: "/"}}}}})
					f.Proxy.Role(&config.Role{Name: "test", Bindings: []*config.Binding{{Backend: "test", Permission: "all"}}})
					f.Proxy.User(&database.User{Id: "test@f110.dev", Roles: []string{"test"}})
				})

				s.It("should close connection", func(m *framework.Matcher) {
					f.Agents.Authorized("test@f110.dev").Get(m, fmt.Sprintf("https://unknown.%s", f.Proxy.Domain))
				})
			})

			s.Context("by unauthenticated agent", func(s *framework.Scenario) {
				s.Subject(func(m *framework.Matcher) {
					f.Agents.Unauthorized().Get(m, fmt.Sprintf("https://unknown.%s", f.Proxy.Domain))
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
					f.Agents.Unauthorized().Get(m, fmt.Sprintf("https://test.%s", f.Proxy.Domain))
				})

				s.It("should redirect to IdP", func(m *framework.Matcher) {
					m.Equal(http.StatusSeeOther, m.LastResponse().StatusCode)
					u, err := m.LastResponse().Location()
					m.NoError(err)
					m.Equal(fmt.Sprintf("https://test.%s/", f.Proxy.Domain), u.Query().Get("from"))
				})
			})

			s.Context("by authenticated user", func(s *framework.Scenario) {
				s.Context("who allowed an access", func(s *framework.Scenario) {
					s.Subject(func(m *framework.Matcher) {
						f.Agents.Authorized("test@f110.dev").Get(m, fmt.Sprintf("https://test.%s/index.html", f.Proxy.Domain))
					})

					s.It("should proxy to backend", func(m *framework.Matcher) {
						m.Equal(http.StatusBadGateway, m.LastResponse().StatusCode, "returns status 502 (BadGateway) because the upstream is down")
					})
				})

				s.Context("who not allowed an access", func(s *framework.Scenario) {
					s.Subject(func(m *framework.Matcher) {
						f.Agents.Authorized("test2@f110.dev").Get(m, fmt.Sprintf("https://test.%s", f.Proxy.Domain))
					})

					s.It("should not proxy to the backend", func(m *framework.Matcher) {
						m.Equal(http.StatusUnauthorized, m.LastResponse().StatusCode)
					})
				})
			})
		})
	})
}
