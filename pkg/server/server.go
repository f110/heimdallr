package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/f110/lagrangian-proxy/pkg/frontproxy"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/connector"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
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

type ChildServer interface {
	Route(mux *httprouter.Router)
}

type HostMultiplexer struct {
	Config *config.Config

	frontProxy http.Handler
	utilities  http.Handler
}

func NewHostMultiplexer(conf *config.Config, frontProxy, utilities http.Handler) *HostMultiplexer {
	return &HostMultiplexer{Config: conf, frontProxy: frontProxy, utilities: utilities}
}

func (h *HostMultiplexer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Host == h.Config.General.ServerName {
		h.utilities.ServeHTTP(w, req)
		return
	}

	h.frontProxy.ServeHTTP(w, req)
}

type Server struct {
	Config *config.Config

	server    *http.Server
	connector *connector.Server
}

func New(conf *config.Config, frontProxy *frontproxy.FrontendProxy, c *connector.Server, child ...ChildServer) *Server {
	mux := httprouter.New()
	for _, v := range child {
		v.Route(mux)
	}

	hostMultiplexer := NewHostMultiplexer(conf, frontProxy, mux)

	return &Server{
		Config: conf,
		server: &http.Server{
			ErrorLog: logger.CompatibleLogger,
			Handler:  hostMultiplexer,
			TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){
				connector.ProtocolName:          c.Accept,
				frontproxy.SocketProxyNextProto: frontProxy.Accept,
			},
		},
		connector: c,
	}
}

func (s *Server) Start() error {
	l, err := net.Listen("tcp", s.Config.General.Bind)
	if err != nil {
		return err
	}
	listener := tls.NewListener(l, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: allowCipherSuites,
		Certificates: []tls.Certificate{s.Config.General.Certificate},
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    s.Config.General.CertificateAuthority.CertPool,
		NextProtos:   []string{connector.ProtocolName, frontproxy.SocketProxyNextProto, http2.NextProtoTLS},
	})

	if err := http2.ConfigureServer(s.server, nil); err != nil {
		return err
	}

	logger.Log.Info("Start Server", zap.String("listen", s.Config.General.Bind))
	return s.server.Serve(listener)
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}

	logger.Log.Info("Shutdown Server")
	return s.server.Shutdown(ctx)
}
