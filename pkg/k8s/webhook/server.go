package webhook

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"

	"github.com/Masterminds/semver/v3"
	"go.f110.dev/xerrors"
	admissionv1 "k8s.io/api/admission/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sjson "k8s.io/apimachinery/pkg/runtime/serializer/json"

	"go.f110.dev/heimdallr/pkg/k8s/api/etcdv1alpha2"
	"go.f110.dev/heimdallr/pkg/logger"
)

var scheme = runtime.NewScheme()

type Server struct {
	*http.Server

	cert string
	key  string

	listener   net.Listener
	serializer *k8sjson.Serializer
	converter  *Converter
}

func NewServer(addr, cert, key string) *Server {
	s := &Server{
		cert:       cert,
		key:        key,
		serializer: k8sjson.NewSerializerWithOptions(k8sjson.DefaultMetaFactory, scheme, scheme, k8sjson.SerializerOptions{}),
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
		logger.Log.Warn("Unexpected content-type", slog.String("content-type", req.Header.Get("Content-Type")))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		logger.Log.Warn("Failed read body", slog.Any("error", err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	conversionReview := &apiextensionsv1.ConversionReview{}
	_, _, err = s.serializer.Decode(body, nil, conversionReview)
	if err != nil {
		logger.Log.Warn("Failed parse request", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	res := &apiextensionsv1.ConversionReview{
		TypeMeta: conversionReview.TypeMeta,
		Response: s.converter.Convert(conversionReview.Request),
	}

	if err := s.serializer.Encode(res, w); err != nil {
		logger.Log.Warn("Failed encode response body", slog.Any("error", err))
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

	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		logger.Log.Warn("Failed read request body", slog.Any("error", err))
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
	if err := validate(admissionReview.Request); err != nil {
		res.Response.Allowed = false
		res.Response.Result = &metav1.Status{Status: metav1.StatusFailure, Message: err.Error()}
	}

	if err := s.serializer.Encode(res, w); err != nil {
		logger.Log.Warn("Failed encode response body", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *Server) Listen() error {
	cert, err := tls.LoadX509KeyPair(s.cert, s.key)
	if err != nil {
		return xerrors.WithStack(err)
	}
	s.Server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}

	l, err := net.Listen("tcp", s.Server.Addr)
	if err != nil {
		return xerrors.WithStack(err)
	}
	s.listener = l

	return nil
}

func (s *Server) Start() error {
	if s.listener == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}

	logger.Log.Info("Start webhook server", slog.String("addr", s.Server.Addr))
	return s.Server.ServeTLS(s.listener, "", "")
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.Server.Shutdown(ctx)
}

var minimumEtcdVersion = semver.MustParse("v3.4.0")

func validate(req *admissionv1.AdmissionRequest) error {
	if req.Kind.Group != etcdv1alpha2.GroupName || req.Kind.Kind != "EtcdCluster" || req.SubResource != "" {
		return nil
	}

	obj := &struct {
		Spec struct {
			Version string `json:"version"`
		} `json:"spec"`
	}{}
	if err := json.Unmarshal(req.Object.Raw, obj); err != nil {
		return xerrors.WithStack(err)
	}
	if obj.Spec.Version == "" {
		return nil
	}
	v, err := semver.NewVersion(obj.Spec.Version)
	if err != nil {
		return xerrors.NewfWithStack("invalid etcd version: %s", obj.Spec.Version)
	}
	if v.LessThan(minimumEtcdVersion) {
		return xerrors.NewfWithStack("etcd %s is not supported. %s or later is required", obj.Spec.Version, minimumEtcdVersion.Original())
	}

	return nil
}
