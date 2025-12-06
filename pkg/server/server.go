package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	"go.f110.dev/xerrors"
	"go.uber.org/zap"
	"golang.org/x/net/http2"

	"go.f110.dev/heimdallr/pkg/authproxy"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/connector"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
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
	Config *configv2.Config

	authProxy http.Handler
	utilities http.Handler
}

func NewHostMultiplexer(conf *configv2.Config, authProxy, utilities http.Handler) *HostMultiplexer {
	return &HostMultiplexer{Config: conf, authProxy: authProxy, utilities: utilities}
}

func (h *HostMultiplexer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host := req.Host
	if strings.Contains(host, ":") {
		s := strings.Split(host, ":")
		host = s[0]
	}

	if host == h.Config.AccessProxy.ServerNameHost {
		h.utilities.ServeHTTP(w, req)
		return
	}

	h.authProxy.ServeHTTP(w, req)
}

type Server struct {
	Config *configv2.Config

	server          *http.Server
	connector       *connector.Server
	clusterDatabase database.ClusterDatabase
}

func New(conf *configv2.Config, cluster database.ClusterDatabase, authProxy *authproxy.AuthProxy, c *connector.Server, child ...ChildServer) *Server {
	mux := httprouter.New()
	for _, v := range child {
		v.Route(mux)
	}

	hostMultiplexer := NewHostMultiplexer(conf, authProxy, mux)
	return &Server{
		Config: conf,
		server: &http.Server{
			ErrorLog:    logger.CompatibleLogger,
			IdleTimeout: 10 * time.Minute,
			Handler:     hostMultiplexer,
			TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){
				connector.ProtocolName:         c.Accept,
				authproxy.SocketProxyNextProto: authProxy.Accept,
			},
		},
		connector:       c,
		clusterDatabase: cluster,
	}
}

func (s *Server) Start() error {
	l, err := net.Listen("tcp", s.Config.AccessProxy.HTTP.Bind)
	if err != nil {
		return xerrors.WithStack(err)
	}
	listener := tls.NewListener(l, &tls.Config{
		MinVersion:     tls.VersionTLS12,
		CipherSuites:   allowCipherSuites,
		GetCertificate: s.Config.AccessProxy.HTTP.Certificate.GetCertificate,
		ClientAuth:     tls.RequestClientCert,
		ClientCAs:      s.Config.CertificateAuthority.CertPool,
		NextProtos:     []string{connector.ProtocolName, authproxy.SocketProxyNextProto, http2.NextProtoTLS},
	})

	if err := http2.ConfigureServer(s.server, nil); err != nil {
		return xerrors.WithStack(err)
	}

	if err := s.clusterDatabase.Join(context.Background()); err != nil {
		return err
	}
	logger.Log.Info("Start Server", zap.String("listen", s.Config.AccessProxy.HTTP.Bind))

	if s.Config.AccessProxy.HTTP.BindHttp != "" {
		l, err := net.Listen("tcp", s.Config.AccessProxy.HTTP.BindHttp)
		if err != nil {
			return xerrors.WithStack(err)
		}
		logger.Log.Info("Start HTTP Server", zap.String("listen", s.Config.AccessProxy.HTTP.BindHttp))
		go s.server.Serve(l)
	}
	if err := s.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return xerrors.WithStack(err)
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}

	s.clusterDatabase.Leave(ctx)
	logger.Log.Info("Shutdown Server")
	return xerrors.WithStack(s.server.Shutdown(ctx))
}
