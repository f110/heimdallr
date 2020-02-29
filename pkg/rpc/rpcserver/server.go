package rpcserver

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"sync"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/f110/lagrangian-proxy/pkg/auth"
	"github.com/f110/lagrangian-proxy/pkg/cert"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc"
	"github.com/f110/lagrangian-proxy/pkg/rpc/rpcservice"
)

var (
	registry     = prometheus.NewRegistry()
	registerOnce sync.Once
)

type Server struct {
	Config *config.Config

	server        *grpc.Server
	privKey       crypto.PrivateKey
	serverMetrics *grpc_prometheus.ServerMetrics
}

func unaryAccessLogInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	logger.Log.Debug("Unary", zap.String("method", info.FullMethod))
	return handler(ctx, req)
}

func streamAccessLogInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	logger.Log.Debug("Stream", zap.String("method", info.FullMethod))
	return handler(srv, ss)
}

func NewServer(conf *config.Config, user database.UserDatabase, token database.TokenDatabase, cluster database.ClusterDatabase,
	relay database.RelayLocator, ca database.CertificateAuthority, isReady func() bool) *Server {
	r := grpc_prometheus.NewServerMetrics()
	grpc_zap.ReplaceGrpcLoggerV2(logger.Log)
	s := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			unaryAccessLogInterceptor,
			auth.UnaryInterceptor,
			r.UnaryServerInterceptor(),
		)),
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(
			streamAccessLogInterceptor,
			auth.StreamInterceptor,
			r.StreamServerInterceptor(),
		)),
	)
	rpc.RegisterClusterServer(s, rpcservice.NewClusterService(user, token, cluster, relay))
	rpc.RegisterAdminServer(s, rpcservice.NewAdminService(conf, user, ca))
	rpc.RegisterCertificateAuthorityServer(s, rpcservice.NewCertificateAuthorityService(conf, ca))
	rpc.RegisterAuthorityServer(s, rpcservice.NewAuthorityService(conf))
	healthpb.RegisterHealthServer(s, rpcservice.NewHealthService(isReady))
	r.InitializeMetrics(s)
	registerOnce.Do(func() {
		registry.MustRegister(r)
		registry.MustRegister(prometheus.NewGoCollector())
	})

	return &Server{
		Config:        conf,
		server:        s,
		serverMetrics: r,
	}
}

func (s *Server) Start() error {
	logger.Log.Info("Start RPC server", zap.String("listen", s.Config.RPCServer.Bind), zap.String("hostname", s.Config.General.ServerNameHost))
	c, privKey, err := cert.GenerateServerCertificate(
		s.Config.General.CertificateAuthority.Certificate,
		s.Config.General.CertificateAuthority.PrivateKey,
		[]string{s.Config.General.ServerNameHost},
	)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	b, err := x509.MarshalECPrivateKey(privKey.(*ecdsa.PrivateKey))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	key := new(bytes.Buffer)
	if err := pem.Encode(key, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	pemEncodedPrivateKey := key.Bytes()
	s.privKey = privKey

	cb := new(bytes.Buffer)
	if err := pem.Encode(cb, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
		return xerrors.Errorf(": %v", err)
	}

	l, err := net.Listen("tcp", s.Config.RPCServer.Bind)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	tlsCert, err := tls.X509KeyPair(cb.Bytes(), pemEncodedPrivateKey)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	listener := tls.NewListener(l, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})

	go func() {
		if s.Config.RPCServer.MetricsBind == "" {
			return
		}

		handler := promhttp.InstrumentMetricHandler(registry, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		mux := http.NewServeMux()
		mux.Handle("/metrics", handler)
		logger.Log.Info("Start RPC metrics server", zap.String("listen", s.Config.RPCServer.MetricsBind))
		http.ListenAndServe(s.Config.RPCServer.MetricsBind, mux)
	}()

	return s.server.Serve(listener)
}

func (s *Server) Shutdown(ctx context.Context) error {
	logger.Log.Info("Shutdown RPC server")
	s.server.GracefulStop()
	return nil
}
