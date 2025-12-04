package rpcserver

import (
	"context"
	"crypto"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/pprof"
	"sync"

	grpczap "github.com/grpc-ecosystem/go-grpc-middleware/providers/zap/v2"
	middleware "github.com/grpc-ecosystem/go-grpc-middleware/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.f110.dev/xerrors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"go.f110.dev/heimdallr/pkg/auth"
	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/rpc"
	"go.f110.dev/heimdallr/pkg/rpc/rpcservice"
)

var (
	registry     = prometheus.NewRegistry()
	registerOnce sync.Once
)

type Server struct {
	Config *configv2.Config

	ca            *cert.CertificateAuthority
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

func NewServer(
	conf *configv2.Config,
	user database.UserDatabase,
	token database.TokenDatabase,
	cluster database.ClusterDatabase,
	relay database.RelayLocator,
	ca *cert.CertificateAuthority,
	isReady func() bool,
) *Server {
	r := grpc_prometheus.NewServerMetrics()
	s := grpc.NewServer(
		grpc.UnaryInterceptor(middleware.ChainUnaryServer(
			unaryAccessLogInterceptor,
			auth.UnaryInterceptor,
			r.UnaryServerInterceptor(),
			logging.UnaryServerInterceptor(grpczap.InterceptorLogger(logger.Log)),
		)),
		grpc.StreamInterceptor(middleware.ChainStreamServer(
			streamAccessLogInterceptor,
			auth.StreamInterceptor,
			r.StreamServerInterceptor(),
			logging.StreamServerInterceptor(grpczap.InterceptorLogger(logger.Log)),
		)),
	)
	rpc.RegisterClusterServer(s, rpcservice.NewClusterService(user, token, cluster, relay))
	rpc.RegisterAdminServer(s, rpcservice.NewAdminService(conf, user))
	rpc.RegisterCertificateAuthorityServer(s, rpcservice.NewCertificateAuthorityService(conf, ca))
	rpc.RegisterUserServer(s, rpcservice.NewUserService(conf))
	healthpb.RegisterHealthServer(s, rpcservice.NewHealthService(isReady))
	r.InitializeMetrics(s)
	registerOnce.Do(func() {
		registry.MustRegister(r)
		registry.MustRegister(prometheus.NewGoCollector())
	})

	return &Server{
		Config:        conf,
		ca:            ca,
		server:        s,
		serverMetrics: r,
	}
}

func (s *Server) Start() error {
	logger.Log.Info("Start RPC server", zap.String("listen", s.Config.RPCServer.Bind), zap.String("hostname", rpc.ServerHostname))
	serverCert, privKey, err := s.ca.NewServerCertificate(rpc.ServerHostname)
	if err != nil {
		return err
	}

	l, err := net.Listen("tcp", s.Config.RPCServer.Bind)
	if err != nil {
		return xerrors.WithStack(err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{serverCert.Raw},
		PrivateKey:  privKey,
	}
	listener := tls.NewListener(l, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h2"},
	})

	go func() {
		if s.Config.RPCServer.MetricsBind == "" {
			return
		}

		handler := promhttp.InstrumentMetricHandler(registry, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		mux := http.NewServeMux()
		mux.Handle("/metrics", handler)
		mux.HandleFunc("/pprof/", pprof.Index)
		mux.HandleFunc("/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/pprof/profile", pprof.Profile)
		mux.HandleFunc("/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/pprof/trace", pprof.Trace)
		logger.Log.Info("Start RPC metrics and pprof server", zap.String("listen", s.Config.RPCServer.MetricsBind))
		http.ListenAndServe(s.Config.RPCServer.MetricsBind, mux)
	}()

	return s.server.Serve(listener)
}

func (s *Server) Shutdown(_ context.Context) error {
	logger.Log.Info("Shutdown RPC server")
	s.server.GracefulStop()
	return nil
}
