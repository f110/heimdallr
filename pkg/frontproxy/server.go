package frontproxy

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/xerrors"
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
	server *http.Server

	httpProxy   *HttpProxy
	socketProxy *SocketProxy
}

func NewFrontendProxy(conf *config.Config) *FrontendProxy {
	s := NewSocketProxy(conf)
	h := NewHttpProxy(conf)

	p := &FrontendProxy{
		Config: conf,
		server: &http.Server{
			ErrorLog: logger.CompatibleLogger,
			TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){
				SocketProxyNextProto: s.Accept,
			},
		},
		httpProxy:   h,
		socketProxy: s,
	}
	p.server.Handler = p

	return p
}

func (p *FrontendProxy) Serve() error {
	if err := http2.ConfigureServer(p.server, nil); err != nil {
		return err
	}

	l, err := net.Listen("tcp", p.Config.FrontendProxy.Bind)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	listener := tls.NewListener(l, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: allowCipherSuites,
		Certificates: []tls.Certificate{p.Config.FrontendProxy.Certificate},
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    p.Config.General.CertificateAuthority.CertPool,
		NextProtos:   []string{SocketProxyNextProto, http2.NextProtoTLS},
	})

	logger.Log.Info("Start FrontendProxy", zap.String("listen", p.Config.FrontendProxy.Bind))
	return p.server.Serve(listener)
}

func (p *FrontendProxy) Shutdown(ctx context.Context) error {
	if p.server == nil {
		return nil
	}

	logger.Log.Info("Shutdown FrontendProxy")
	return p.server.Shutdown(ctx)
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
