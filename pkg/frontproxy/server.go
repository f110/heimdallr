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

var allowCipherSuites = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
}

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
