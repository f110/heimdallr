package api

import (
	"context"
	"net/http"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/frontproxy"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"
)

type Server struct {
	*http.Server
}

func NewServer(ctx context.Context, conf *config.RPCServer, conn *grpc.ClientConn) (*Server, error) {
	mux := runtime.NewServeMux(runtime.WithIncomingHeaderMatcher(func(key string) (name string, ok bool) {
		switch key {
		case frontproxy.TokenHeaderName, frontproxy.UserIdHeaderName:
			return rpc.JwtTokenMetadataKey, true
		}
		return "", false
	}))
	if err := rpc.RegisterCertificateAuthorityHandler(ctx, mux, conn); err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	s := &http.Server{
		Addr:     conf.RestBind,
		ErrorLog: logger.CompatibleLogger,
		Handler:  mux,
	}

	return &Server{Server: s}, nil
}

func (s *Server) Start() error {
	logger.Log.Info("Start REST API server", zap.String("listen", s.Server.Addr))
	return s.Server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	logger.Log.Info("Shutdown REST API server")
	return s.Server.Shutdown(ctx)
}
