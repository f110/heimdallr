package internalapi

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
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
	mux.GET("/users/:username/ssh_keys", r.requireAuthn(r.SSHKeys))
	mux.GET("/users/:username/gpg_key", r.requireAuthn(r.GPGKey))
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
			Roots:     r.Config.CertificateAuthority.Local.CertPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next(w, req, params)
	}
}

func (r *ResourceServer) SSHKeys(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	loginName := params.ByName("username")
	if loginName == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	identity := loginName
	id, err := r.userDatabase.GetIdentityByLoginName(req.Context(), loginName)
	// If passed identity, not login name, GetIdentityByLoginName will return ErrUserNotFound.
	// At this point, ErrUserNotFound is ignored because "username" may be the identity.
	if err != nil && err != database.ErrUserNotFound {
		logger.Log.Warn("Failed get identity", zap.Error(err), zap.String("login_name", loginName))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if id != "" {
		identity = id
	}

	keys, err := r.userDatabase.GetSSHKeys(req.Context(), identity)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	io.WriteString(w, keys.Keys)
}

func (r *ResourceServer) GPGKey(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	loginName := params.ByName("username")
	if loginName == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	identity := loginName
	id, err := r.userDatabase.GetIdentityByLoginName(req.Context(), loginName)
	if err != nil && err != database.ErrUserNotFound {
		logger.Log.Warn("Failed get identity", zap.Error(err), zap.String("login_name", loginName))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if id != "" {
		identity = id
	}

	keys, err := r.userDatabase.GetGPGKey(req.Context(), identity)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	io.WriteString(w, keys.Key)
}
