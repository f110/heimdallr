package test

import (
	"context"
	"net/http"
	"testing"

	"go.f110.dev/heimdallr/operator/e2e/framework"
	"go.f110.dev/heimdallr/pkg/testing/btesting"
)

func TestProxyController(t *testing.T) {
	t.Parallel()
	f := framework.New(t, RESTConfig)
	defer f.Execute()

	f.Describe("ProxyController", func(s *btesting.Scenario) {
		const testUserId = "e2e@f110.dev"
		s.BeforeAll(func(_ context.Context, m *btesting.Matcher) { f.Proxy.Setup(m, testUserId) })

		s.Step("send a request", func(s *btesting.Scenario) {
			s.Subject(func(_ context.Context, m *btesting.Matcher) {
				f.Proxy.Agent(true).Get(m, f.Proxy.Backend, nil)
			})

			s.It("should return status OK", func(_ context.Context, m *btesting.Matcher) {
				m.StatusCode(http.StatusOK)
			})

			s.It("should return Server header", func(_ context.Context, m *btesting.Matcher) {
				m.Contains(m.LastResponse().Header.Get("Server"), "nginx")
			})
		})

		s.Step("send a request without client credential", func(s *btesting.Scenario) {
			s.Subject(func(_ context.Context, m *btesting.Matcher) {
				f.Proxy.Agent(false).Get(m, f.Proxy.Backend, nil)
			})

			s.It("should return status see other", func(_ context.Context, m *btesting.Matcher) {
				m.StatusCode(http.StatusSeeOther)
			})
		})

		s.Step("send a request to dashboard", func(s *btesting.Scenario) {
			s.Subject(func(_ context.Context, m *btesting.Matcher) {
				f.Proxy.Agent(true).GetDashboard(m)
			})

			s.It("should return status OK", func(_ context.Context, m *btesting.Matcher) {
				m.StatusCode(http.StatusOK)
			})
		})
	})
}
