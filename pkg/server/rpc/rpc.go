package rpc

import (
	"context"
	"net/http"

	"github.com/f110/lagrangian-proxy/pkg/config"

	"github.com/f110/lagrangian-proxy/pkg/auth"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

func unaryAccessLogInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	logger.Log.Debug("Unary", zap.String("method", info.FullMethod))
	return handler(ctx, req)
}

func streamAccessLogInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	logger.Log.Debug("Stream", zap.String("method", info.FullMethod))
	return handler(srv, ss)
}

type Server struct {
	internal *grpc.Server
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.internal.ServeHTTP(w, req)
}

func NewServer(conf *config.Config, user database.UserDatabase, token database.TokenDatabase, cluster database.ClusterDatabase, relay database.RelayLocator) *Server {
	s := grpc.NewServer(
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			unaryAccessLogInterceptor,
			auth.UnaryInterceptor,
		)),
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(
			streamAccessLogInterceptor,
			auth.StreamInterceptor,
		)),
	)
	rpc.RegisterClusterServer(s, rpc.NewClusterService(user, token, cluster, relay))
	rpc.RegisterAdminServer(s, rpc.NewAdminService(conf, user))
	return &Server{internal: s}
}
