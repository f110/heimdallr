package rpc

import (
	"net/http"

	"github.com/f110/lagrangian-proxy/pkg/auth"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/rpc"
	"google.golang.org/grpc"
)

type Server struct {
	internal *grpc.Server
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.internal.ServeHTTP(w, req)
}

func NewServer(user database.UserDatabase, cluster database.ClusterDatabase) *Server {
	s := grpc.NewServer(
		grpc.UnaryInterceptor(auth.UnaryInterceptor),
		grpc.StreamInterceptor(auth.StreamInterceptor),
	)
	rpc.RegisterClusterServer(s, rpc.NewClusterService(cluster))
	rpc.RegisterUserServer(s, rpc.NewUserService(user))
	return &Server{internal: s}
}
