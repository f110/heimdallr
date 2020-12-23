package webhook

import (
	"context"
	"io/ioutil"
	"net/http"

	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"

	"go.f110.dev/heimdallr/pkg/logger"
)

var scheme = runtime.NewScheme()

type Server struct {
	*http.Server

	cert string
	key  string

	serializer *json.Serializer
	converter  *Converter
}

func NewServer(addr, cert, key string) *Server {
	s := &Server{
		cert:       cert,
		key:        key,
		serializer: json.NewSerializerWithOptions(json.DefaultMetaFactory, scheme, scheme, json.SerializerOptions{}),
		converter:  DefaultConverter,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/favicon.ico", http.NotFound)
	mux.HandleFunc("/conversion", s.Conversion)
	mux.HandleFunc("/validate", s.Validate)
	s.Server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return s
}

func (s *Server) Conversion(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if req.Header.Get("Content-Type") != "application/json" {
		logger.Log.Warn("Unexpected content-type", zap.String("content-type", req.Header.Get("Content-Type")))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		logger.Log.Warn("Failed read body", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	conversionReview := &apiextensionsv1.ConversionReview{}
	_, _, err = s.serializer.Decode(body, nil, conversionReview)
	if err != nil {
		logger.Log.Warn("Failed parse request", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	res := &apiextensionsv1.ConversionReview{
		TypeMeta: conversionReview.TypeMeta,
		Response: s.converter.Convert(conversionReview.Request),
	}

	if err := s.serializer.Encode(res, w); err != nil {
		logger.Log.Warn("Failed encode response body", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Server) Validate(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if req.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		logger.Log.Warn("Failed read request body", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	admissionReview := &admissionv1.AdmissionReview{}
	if _, _, err := s.serializer.Decode(body, nil, admissionReview); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	res := &admissionv1.AdmissionReview{
		TypeMeta: admissionReview.TypeMeta,
		Response: &admissionv1.AdmissionResponse{
			UID:     admissionReview.Request.UID,
			Allowed: true,
		},
	}

	if err := s.serializer.Encode(res, w); err != nil {
		logger.Log.Warn("Failed encode response body", zap.Error(err))
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
