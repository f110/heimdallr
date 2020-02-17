package frontproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/rpc/rpcclient"
	"github.com/f110/lagrangian-proxy/pkg/rpc/rpctestutil"
)

type dummyHttpProxy struct {
	requests        []*http.Request
	webhookRequests []*http.Request
}

func (d *dummyHttpProxy) ServeHTTP(_ context.Context, _ http.ResponseWriter, req *http.Request) {
	if d.requests == nil {
		d.requests = make([]*http.Request, 0)
	}

	d.requests = append(d.requests, req)
}

func (d *dummyHttpProxy) ServeGithubWebHook(_ context.Context, _ http.ResponseWriter, req *http.Request) {
	if d.webhookRequests == nil {
		d.webhookRequests = make([]*http.Request, 0)
	}

	d.webhookRequests = append(d.webhookRequests, req)
}

func TestNewFrontendProxy(t *testing.T) {
	authority := rpctestutil.NewAuthorityClient()
	c := rpcclient.NewWithClient(nil, nil, authority, nil)

	v := NewFrontendProxy(&config.Config{Logger: &config.Logger{}}, nil, c)
	if v == nil {
		t.Fatal("NewFrontendProxy should return a value")
	}
}

func TestFrontendProxy_ServeHTTP(t *testing.T) {
	mockProxy := &dummyHttpProxy{}
	v := NewFrontendProxy(&config.Config{
		Logger: &config.Logger{},
	}, nil, nil)
	v.httpProxy = mockProxy

	t.Run("webhook", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodPost, "http://test.example.com", nil)
		req.Header.Set("X-Hub-Signature", "test")
		r := httptest.NewRecorder()
		v.ServeHTTP(r, req)

		if len(mockProxy.webhookRequests) == 0 {
			t.Errorf("should call ServeGithubWebHook but not")
		}
	})

	t.Run("other", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodPost, "http://test.example.com", nil)
		r := httptest.NewRecorder()
		v.ServeHTTP(r, req)

		if len(mockProxy.requests) == 0 {
			t.Errorf("should call ServeHTTP but not")
		}
	})
}
