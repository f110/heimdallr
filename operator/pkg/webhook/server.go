package webhook

import (
	"context"
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"

	"go.f110.dev/heimdallr/pkg/logger"
)

type Server struct {
	*http.Server

	cert string
	key  string
}

func NewServer(addr, cert, key string) *Server {
	s := &Server{
		cert: cert,
		key:  key,
	}
	s.Server = &http.Server{
		Addr:    addr,
		Handler: s,
	}

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if req.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	event := &admissionv1.AdmissionReview{}
	if err := json.NewDecoder(req.Body).Decode(&event); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	res := &admissionv1.AdmissionReview{
		TypeMeta: event.TypeMeta,
		Response: &admissionv1.AdmissionResponse{
			UID:     event.Request.UID,
			Allowed: true,
		},
	}
	if err := json.NewEncoder(w).Encode(res); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Server) Start() error {
	logger.Log.Info("Start webhook server", zap.String("addr", s.Server.Addr))
	return s.Server.ListenAndServeTLS(s.cert, s.key)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.Server.Shutdown(ctx)
}
