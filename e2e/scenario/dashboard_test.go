package scenario

import (
	"context"
	"net/http"
	"testing"

	"go.f110.dev/heimdallr/e2e/framework"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/testing/btesting"
)

const (
	listUsersProcedure = "/dashboard.bff.AdminService/ListUsers"
	listRolesProcedure = "/dashboard.bff.AdminService/ListRoles"
)

func TestDashboard(t *testing.T) {
	f := framework.New(t)
	defer f.Execute()

	f.Describe("Dashboard", func(s *btesting.Scenario) {
		s.BeforeEach(func(ctx context.Context, m *btesting.Matcher) { m.Must(f.Proxy.Reload(ctx)) })
		s.Defer(func() { f.Proxy.Cleanup() })

		s.Context("by root user", func(s *btesting.Scenario) {
			s.BeforeAll(func(_ context.Context, _ *btesting.Matcher) { f.Proxy.Backend(f.Proxy.DashboardBackend()) })
			s.AfterAll(func(_ context.Context, _ *btesting.Matcher) { f.Proxy.ClearConf() })

			s.Context("call ListUsers", func(s *btesting.Scenario) {
				s.Subject(func(_ context.Context, m *btesting.Matcher) {
					f.Agents.Authorized(framework.RootUserId).PostJSON(m, f.Proxy.URL("dashboard", listUsersProcedure), struct{}{})
				})

				s.It("should return StatusOK", func(_ context.Context, m *btesting.Matcher) {
					m.Equal(http.StatusOK, m.LastResponse().StatusCode)
				})
			})

			s.Context("call ListRoles", func(s *btesting.Scenario) {
				s.Subject(func(_ context.Context, m *btesting.Matcher) {
					f.Agents.Authorized(framework.RootUserId).PostJSON(m, f.Proxy.URL("dashboard", listRolesProcedure), struct{}{})
				})

				s.It("should return StatusOK", func(_ context.Context, m *btesting.Matcher) {
					m.Equal(http.StatusOK, m.LastResponse().StatusCode)
				})
			})
		})

		s.Context("by admin user", func(s *btesting.Scenario) {
			s.BeforeAll(func(_ context.Context, _ *btesting.Matcher) {
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
			})
			s.AfterAll(func(_ context.Context, _ *btesting.Matcher) { f.Proxy.ClearConf() })

			s.Context("call ListUsers", func(s *btesting.Scenario) {
				s.Subject(func(_ context.Context, m *btesting.Matcher) {
					f.Agents.Authorized("admin@f110.dev").PostJSON(m, f.Proxy.URL("dashboard", listUsersProcedure), struct{}{})
				})

				s.It("should return StatusOK", func(_ context.Context, m *btesting.Matcher) {
					m.Equal(http.StatusOK, m.LastResponse().StatusCode)
				})
			})

			s.Context("call ListRoles", func(s *btesting.Scenario) {
				s.Subject(func(_ context.Context, m *btesting.Matcher) {
					f.Agents.Authorized("admin@f110.dev").PostJSON(m, f.Proxy.URL("dashboard", listRolesProcedure), struct{}{})
				})

				s.It("should return StatusOK", func(_ context.Context, m *btesting.Matcher) {
					m.Equal(http.StatusOK, m.LastResponse().StatusCode)
				})
			})
		})

		s.Context("by non-admin user", func(s *btesting.Scenario) {
			s.BeforeAll(func(_ context.Context, _ *btesting.Matcher) {
				dashboard := f.Proxy.DashboardBackend()
				f.Proxy.Backend(dashboard)
				f.Proxy.Role(&configv2.Role{Name: "admin", Bindings: []*configv2.Binding{
					{Backend: dashboard.Name, Permission: dashboard.Permissions[0].Name},
				}})
				f.Proxy.Role(&configv2.Role{Name: "user"})
				f.Proxy.User(&database.User{Id: "test@f110.dev", Roles: []string{"user"}})
			})
			s.AfterAll(func(_ context.Context, _ *btesting.Matcher) { f.Proxy.ClearConf() })

			s.Context("call ListUsers", func(s *btesting.Scenario) {
				s.Subject(func(_ context.Context, m *btesting.Matcher) {
					f.Agents.Authorized("test@f110.dev").PostJSON(m, f.Proxy.URL("dashboard", listUsersProcedure), struct{}{})
				})

				s.It("should return StatusUnauthorized", func(_ context.Context, m *btesting.Matcher) {
					m.Equal(http.StatusUnauthorized, m.LastResponse().StatusCode)
				})
			})

			s.Context("call ListRoles", func(s *btesting.Scenario) {
				s.Subject(func(_ context.Context, m *btesting.Matcher) {
					f.Agents.Authorized("test@f110.dev").PostJSON(m, f.Proxy.URL("dashboard", listRolesProcedure), struct{}{})
				})

				s.It("should return StatusUnauthorized", func(_ context.Context, m *btesting.Matcher) {
					m.Equal(http.StatusUnauthorized, m.LastResponse().StatusCode)
				})
			})
		})
	})
}
