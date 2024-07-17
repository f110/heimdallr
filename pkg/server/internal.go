package server

import (
	"context"
	"errors"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"go.f110.dev/xerrors"
	"go.uber.org/zap"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/logger"
)

type Internal struct {
	Config *configv2.Config

	server *http.Server
}

func NewInternal(conf *configv2.Config, child ...ChildServer) *Internal {
	mux := httprouter.New()
	for _, v := range child {
		v.Route(mux)
	}

	return &Internal{
		Config: conf,
		server: &http.Server{
			Addr:     conf.AccessProxy.HTTP.BindInternalApi,
			ErrorLog: logger.CompatibleLogger,
			Handler:  mux,
		},
	}
}

func (s *Internal) Start() error {
	logger.Log.Info("Start Internal server", zap.String("listen", s.Config.AccessProxy.HTTP.BindInternalApi))
	if err := s.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return xerrors.WithStack(s.server.ListenAndServe())
	}
	return nil
}

func (s *Internal) Shutdown(ctx context.Context) error {
	logger.Log.Info("Shutdown Internal server")
	return xerrors.WithStack(s.server.Shutdown(ctx))
}
