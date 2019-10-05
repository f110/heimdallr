package internalapi

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"net/http"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/server"
	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"
)

type ResourceServer struct {
	Config *config.Config
}

var _ server.ChildServer = &ResourceServer{}

func NewResourceServer(conf *config.Config) *ResourceServer {
	return &ResourceServer{Config: conf}
}

func (r *ResourceServer) Route(mux *httprouter.Router) {
	buf := new(bytes.Buffer)
	b, err := x509.MarshalPKIXPublicKey(&r.Config.FrontendProxy.SigningPublicKey)
	if err != nil {
		logger.Log.Error("Failed marshal public key", zap.Error(err))
	}
	if err := pem.Encode(buf, &pem.Block{Type: "PUBLIC KEY", Bytes: b}); err != nil {
		logger.Log.Error("Failed pem encode", zap.Error(err))
	}
	mux.GET("/internal/publickey", func(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(buf.Bytes())
	})
}
