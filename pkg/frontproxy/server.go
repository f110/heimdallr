package frontproxy

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/connector"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
)

type httpProxy interface {
	ServeHTTP(ctx context.Context, w http.ResponseWriter, req *http.Request)
	ServeGithubWebHook(ctx context.Context, w http.ResponseWriter, req *http.Request)
	ServeSlackWebHook(ctx context.Context, w http.ResponseWriter, req *http.Request)
}

type FrontendProxy struct {
	Config *configv2.Config

	httpProxy   httpProxy
	socketProxy *SocketProxy
}

func NewFrontendProxy(conf *configv2.Config, ct *connector.Server, c *rpcclient.Client) *FrontendProxy {
	s := NewSocketProxy(conf, ct)
	h := NewHttpProxy(conf, ct, c)

	p := &FrontendProxy{
		Config:      conf,
		httpProxy:   h,
		socketProxy: s,
	}

	return p
}

func (p *FrontendProxy) Accept(server *http.Server, conn *tls.Conn, handler http.Handler) {
	p.socketProxy.Accept(server, conn, handler)
}

func (p *FrontendProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	requestId := p.requestId()
	ctx := context.WithValue(req.Context(), "dispatch_time", time.Now())
	ctx = context.WithValue(ctx, "request_id", requestId)

	switch {
	case req.Header.Get("X-Hub-Signature") != "":
		p.httpProxy.ServeGithubWebHook(ctx, w, req)
	case req.Header.Get("X-Slack-Signature") != "":
		p.httpProxy.ServeSlackWebHook(ctx, w, req)
	default:
		p.httpProxy.ServeHTTP(ctx, w, req)
	}
}

func (p *FrontendProxy) requestId() string {
	buf := make([]byte, requestIdLength/2)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return ""
	}
	s := sha1.Sum(buf)
	return hex.EncodeToString(s[:])
}
