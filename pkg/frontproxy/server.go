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

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/connector"
)

type FrontendProxy struct {
	Config *config.Config

	httpProxy   *HttpProxy
	socketProxy *SocketProxy
}

func NewFrontendProxy(conf *config.Config, ct *connector.Server) *FrontendProxy {
	s := NewSocketProxy(conf, ct)
	h := NewHttpProxy(conf, ct)

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
