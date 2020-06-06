package internalapi

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"

	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/server"
)

type ResourceServer struct {
	Config *config.Config
}

var _ server.ChildServer = &ResourceServer{}

func NewResourceServer(config *config.Config) (*ResourceServer, error) {
	return &ResourceServer{Config: config}, nil
}

func (r *ResourceServer) Route(mux *httprouter.Router) {
	mux.GET("/internal/publickey", func(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
		b, err := x509.MarshalPKIXPublicKey(&r.Config.General.SigningPublicKey)
		if err != nil {
			logger.Log.Error("Failed marshal public key", zap.Error(err))
		}
		buf := new(bytes.Buffer)
		if err := pem.Encode(buf, &pem.Block{Type: "PUBLIC KEY", Bytes: b}); err != nil {
			logger.Log.Error("Failed pem encode", zap.Error(err))
		}

		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(b)
	})
}
