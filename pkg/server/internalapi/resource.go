package internalapi

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"time"

	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/server"
)

type ResourceServer struct {
	Config       *configv2.Config
	userDatabase database.UserDatabase
}

var _ server.ChildServer = &ResourceServer{}

func NewResourceServer(config *configv2.Config, userDatabase database.UserDatabase) (*ResourceServer, error) {
	return &ResourceServer{Config: config, userDatabase: userDatabase}, nil
}

func (r *ResourceServer) Route(mux *httprouter.Router) {
	mux.GET("/internal/publickey", r.PublicKey)
}

func (r *ResourceServer) PublicKey(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	b, err := x509.MarshalPKIXPublicKey(&r.Config.AccessProxy.Credential.SigningPublicKey)
	if err != nil {
		logger.Log.Error("Failed marshal public key", zap.Error(err))
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "PUBLIC KEY", Bytes: b}); err != nil {
		logger.Log.Error("Failed pem encode", zap.Error(err))
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(buf.Bytes())
}

func (r *ResourceServer) requireAuthn(next httprouter.Handle) func(http.ResponseWriter, *http.Request, httprouter.Params) {
	return func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		if req.TLS == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if len(req.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		cert := req.TLS.PeerCertificates[0]
		if time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, err := cert.Verify(x509.VerifyOptions{
			Roots:     r.Config.CertificateAuthority.CertPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next(w, req, params)
	}
}
