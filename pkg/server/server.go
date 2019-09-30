package server

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

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

type Server struct {
	Config *config.Config

	server    *http.Server
	connector *connector.Server
}

func New(conf *config.Config, c *connector.Server, child ...ChildServer) *Server {
	mux := httprouter.New()
	for _, v := range child {
		v.Route(mux)
	}

	return &Server{
		Config: conf,
		server: &http.Server{
			ErrorLog: logger.CompatibleLogger,
			Handler:  mux,
			TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){
				connector.ProtocolName: c.Accept,
			},
		},
		connector: c,
	}
}

func (s *Server) Start() error {
	l, err := net.Listen("tcp", s.Config.UI.Bind)
	if err != nil {
		return err
	}
	listener := tls.NewListener(l, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: allowCipherSuites,
		Certificates: []tls.Certificate{s.Config.UI.Certificate},
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    s.Config.General.CertificateAuthority.CertPool,
		NextProtos:   []string{connector.ProtocolName, http2.NextProtoTLS},
	})

	if err := http2.ConfigureServer(s.server, nil); err != nil {
		return err
	}

	logger.Log.Info("Start UI Server", zap.String("listen", s.Config.UI.Bind))
	return s.server.Serve(listener)
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}

	logger.Log.Info("Shutdown UI Server")
	return s.server.Shutdown(ctx)
}