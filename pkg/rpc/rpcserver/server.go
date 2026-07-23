package rpcserver

import (
	"context"
	"crypto"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"strings"
	"sync"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.f110.dev/xerrors"
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
	healthServer  *grpc.Server
	privKey       crypto.PrivateKey
	serverMetrics *grpc_prometheus.ServerMetrics
}

func unaryAccessLogInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	logger.Log.Debug("Unary", slog.String("method", info.FullMethod))
	return handler(ctx, req)
}

func streamAccessLogInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	logger.Log.Debug("Stream", slog.String("method", info.FullMethod))
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
		grpc.ChainUnaryInterceptor(
			unaryAccessLogInterceptor,
			auth.UnaryInterceptor,
			r.UnaryServerInterceptor(),
			logging.UnaryServerInterceptor(logger.GRPCInterceptorLogger(logger.Log)),
		),
		grpc.ChainStreamInterceptor(
			streamAccessLogInterceptor,
			auth.StreamInterceptor,
			r.StreamServerInterceptor(),
			logging.StreamServerInterceptor(logger.GRPCInterceptorLogger(logger.Log)),
		),
	)
	rpc.RegisterClusterServer(s, rpcservice.NewClusterService(user, token, cluster, relay))
	rpc.RegisterAdminServer(s, rpcservice.NewAdminService(conf, user))
	rpc.RegisterCertificateAuthorityServer(s, rpcservice.NewCertificateAuthorityService(conf, ca))
	rpc.RegisterUserServer(s, rpcservice.NewUserService(conf))
	r.InitializeMetrics(s)
	registerOnce.Do(func() {
		registry.MustRegister(r)
		registry.MustRegister(prometheus.NewGoCollector())
	})

	healthServer := grpc.NewServer()
	healthpb.RegisterHealthServer(healthServer, rpcservice.NewHealthService(isReady))

	return &Server{
		Config:        conf,
		ca:            ca,
		server:        s,
		healthServer:  healthServer,
		serverMetrics: r,
	}
}

func (s *Server) Start() error {
	logger.Log.Info("Start RPC server", slog.String("listen", s.Config.RPCServer.Bind), slog.String("hostname", rpc.ServerHostname))
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

		metricsServer := &http.Server{
			Addr:      s.Config.RPCServer.MetricsBind,
			Protocols: new(http.Protocols),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
					s.healthServer.ServeHTTP(w, r)
				} else {
					mux.ServeHTTP(w, r)
				}
			}),
		}
		metricsServer.Protocols.SetHTTP1(true)
		metricsServer.Protocols.SetHTTP2(true)
		metricsServer.Protocols.SetUnencryptedHTTP2(true)

		logger.Log.Info("Start RPC metrics and pprof server", slog.String("listen", s.Config.RPCServer.MetricsBind))
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Log.Error("Something occurred", slog.Any("error", err))
		}
	}()

	return s.server.Serve(listener)
}

func (s *Server) Shutdown(_ context.Context) error {
	logger.Log.Info("Shutdown RPC server")
	s.server.GracefulStop()
	return nil
}
