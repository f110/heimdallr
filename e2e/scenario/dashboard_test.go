package scenario

import (
	"net/http"
	"testing"

	"go.f110.dev/heimdallr/e2e/framework"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/testing/btesting"
)

func TestDashboard(t *testing.T) {
	f := framework.New(t)
	defer f.Execute()

	f.Describe("Dashboard", func(s *btesting.Scenario) {
		s.BeforeEach(func(m *btesting.Matcher) bool { return m.Must(f.Proxy.Reload()) })
		s.Defer(func() { f.Proxy.Cleanup() })

		s.Context("by root user", func(s *btesting.Scenario) {
			s.BeforeAll(func(m *btesting.Matcher) bool {
				f.Proxy.Backend(f.Proxy.DashboardBackend())
				return true
			})
			s.AfterAll(func(m *btesting.Matcher) bool { return f.Proxy.ClearConf() })

			s.Context("request /", func(s *btesting.Scenario) {
				s.Subject(func(m *btesting.Matcher) bool {
					return f.Agents.Authorized(framework.RootUserId).Get(m, f.Proxy.URL("dashboard"))
				})

				s.It("should return StatusOK", func(m *btesting.Matcher) bool {
					return m.Equal(http.StatusOK, m.LastResponse().StatusCode)
				})
			})

			s.Context("request /user", func(s *btesting.Scenario) {
				s.Subject(func(m *btesting.Matcher) bool {
					return f.Agents.Authorized(framework.RootUserId).Get(m, f.Proxy.URL("dashboard", "/user"))
				})

				s.It("should return StatusOK", func(m *btesting.Matcher) bool {
					return m.Equal(http.StatusOK, m.LastResponse().StatusCode)
				})
			})
		})

		s.Context("by admin user", func(s *btesting.Scenario) {
			s.BeforeAll(func(m *btesting.Matcher) bool {
				dashboard := f.Proxy.DashboardBackend()
				f.Proxy.Backend(dashboard)
				f.Proxy.RPCPermission(&configv2.RPCPermission{
					Name:  "dashboard-user",
					Allow: []string{"proxy.rpc.admin.*", "proxy.rpc.certificateauthority.*"},
				})
				f.Proxy.Role(&configv2.Role{
					Name: "admin",
					Bindings: []*configv2.Binding{
						{RPC: "dashboard-user"},
						{Backend: dashboard.Name, Permission: dashboard.Permissions[0].Name},
					},
				})
				f.Proxy.User(&database.User{Id: "admin@f110.dev", Roles: []string{"admin"}})
				return true
			})
			s.AfterAll(func(m *btesting.Matcher) bool { return f.Proxy.ClearConf() })

			s.Context("request /", func(s *btesting.Scenario) {
				s.Subject(func(m *btesting.Matcher) bool {
					return f.Agents.Authorized("admin@f110.dev").Get(m, f.Proxy.URL("dashboard"))
				})

				s.It("should return StatusOK", func(m *btesting.Matcher) bool {
					return m.Equal(http.StatusOK, m.LastResponse().StatusCode)
				})
			})

			s.Context("request /user", func(s *btesting.Scenario) {
				s.Subject(func(m *btesting.Matcher) bool {
					return f.Agents.Authorized("admin@f110.dev").Get(m, f.Proxy.URL("dashboard", "/user"))
				})

				s.It("should return StatusOK", func(m *btesting.Matcher) bool {
					return m.Equal(http.StatusOK, m.LastResponse().StatusCode)
				})
			})
		})

		s.Context("by non-admin user", func(s *btesting.Scenario) {
			s.BeforeAll(func(m *btesting.Matcher) bool {
				dashboard := f.Proxy.DashboardBackend()
				f.Proxy.Backend(dashboard)
				f.Proxy.Role(&configv2.Role{Name: "admin", Bindings: []*configv2.Binding{
					{Backend: dashboard.Name, Permission: dashboard.Permissions[0].Name},
				}})
				f.Proxy.Role(&configv2.Role{Name: "user"})
				f.Proxy.User(&database.User{Id: "test@f110.dev", Roles: []string{"user"}})
				return true
			})
			s.AfterAll(func(m *btesting.Matcher) bool { return f.Proxy.ClearConf() })

			s.Context("request /", func(s *btesting.Scenario) {
				s.Subject(func(m *btesting.Matcher) bool {
					return f.Agents.Authorized("test@f110.dev").Get(m, f.Proxy.URL("dashboard"))
				})

				s.It("should return StatusUnauthorized", func(m *btesting.Matcher) bool {
					return m.Equal(http.StatusUnauthorized, m.LastResponse().StatusCode)
				})
			})

			s.Context("request /user", func(s *btesting.Scenario) {
				s.Subject(func(m *btesting.Matcher) bool {
					return f.Agents.Authorized("test@f110.dev").Get(m, f.Proxy.URL("dashboard", "/user"))
				})

				s.It("should return StatusUnauthorized", func(m *btesting.Matcher) bool {
					return m.Equal(http.StatusUnauthorized, m.LastResponse().StatusCode)
				})
			})
		})
	})
}
