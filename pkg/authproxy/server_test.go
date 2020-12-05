package authproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
)

type dummyHttpProxy struct {
	requests        []*http.Request
	webhookRequests []*http.Request
}

var _ httpProxy = &dummyHttpProxy{}

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

func (d *dummyHttpProxy) ServeSlackWebHook(_ context.Context, _ http.ResponseWriter, req *http.Request) {
	if d.webhookRequests == nil {
		d.webhookRequests = make([]*http.Request, 0)
	}

	d.webhookRequests = append(d.webhookRequests, req)
}

func TestNewFrontendProxy(t *testing.T) {
	c := rpcclient.NewWithClient(nil, nil, nil, nil)

	v := NewFrontendProxy(&configv2.Config{Logger: &configv2.Logger{}}, nil, c)
	if v == nil {
		t.Fatal("NewFrontendProxy should return a value")
	}
}

func TestFrontendProxy_ServeHTTP(t *testing.T) {
	mockProxy := &dummyHttpProxy{}
	v := NewFrontendProxy(&configv2.Config{
		Logger: &configv2.Logger{},
	}, nil, nil)
	v.httpProxy = mockProxy

	t.Run("GitHub Webhook", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodPost, "http://test.example.com", nil)
		req.Header.Set("X-Hub-Signature", "test")
		r := httptest.NewRecorder()
		v.ServeHTTP(r, req)

		if len(mockProxy.webhookRequests) == 0 {
			t.Errorf("should call ServeGithubWebHook but not")
		}
	})

	t.Run("Slack Webhook", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodPost, "http://test.example.com", nil)
		req.Header.Set("X-Slack-Signature", "test")
		r := httptest.NewRecorder()
		v.ServeHTTP(r, req)

		if len(mockProxy.webhookRequests) == 0 {
			t.Errorf("should call ServeSlackWebHook but not")
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
