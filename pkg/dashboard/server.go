package dashboard

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"connectrpc.com/connect"
	"go.f110.dev/xerrors"
	"google.golang.org/grpc"

	"go.f110.dev/heimdallr/pkg/authproxy"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
)

type Server struct {
	Config *configv2.Config

	publicKey   crypto.PublicKey
	conn        *grpc.ClientConn
	client      *rpcclient.ClientWithUserToken
	server      *http.Server
	probeServer *http.Server
}

func NewServer(config *configv2.Config, grpcConn *grpc.ClientConn) (*Server, error) {
	publicKey, err := fetchPublicKey(config.Dashboard.PublicKeyUrl)
	if err != nil {
		return nil, err
	}

	s := &Server{
		Config:    config,
		publicKey: publicKey,
		conn:      grpcConn,
		client:    rpcclient.NewClientWithUserToken(grpcConn),
	}

	interceptors := connect.WithInterceptors(newAccessLogInterceptor(), newAuthInterceptor(publicKey))
	mux := http.NewServeMux()
	mux.Handle(NewMeServiceHandler(NewMeService(s.client), interceptors))
	mux.Handle(NewAdminServiceHandler(NewAdminService(s.client), interceptors))
	mux.Handle(NewCertificateServiceHandler(NewCertificateService(s.client), interceptors))
	mux.Handle("GET /cert/download", s.verifyRequest(http.HandlerFunc(s.handleDownloadCert)))
	mux.Handle("GET /cert/ca", s.verifyRequest(http.HandlerFunc(s.handleDownloadCACert)))
	s.server = &http.Server{Addr: config.Dashboard.Bind, Handler: mux}

	probeMux := http.NewServeMux()
	probeMux.HandleFunc("GET /_livez", func(_ http.ResponseWriter, _ *http.Request) {})
	probeMux.HandleFunc("GET /_readyz", s.handleReadiness)
	s.probeServer = &http.Server{Addr: config.Dashboard.ProbeBind, Handler: probeMux}

	return s, nil
}

func fetchPublicKey(url string) (crypto.PublicKey, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	res.Body.Close()

	block, _ := pem.Decode(b)
	if block == nil {
		return nil, xerrors.NewWithStack("failed parse public key")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, xerrors.NewWithStack("failed parse public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return publicKey, nil
}

func (s *Server) Start() error {
	logger.Log.Info("Start dashboard",
		slog.String("listen", s.server.Addr),
		slog.String("probe", s.probeServer.Addr),
	)

	go func() {
		if err := s.probeServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Log.Warn("Probe listener is closed", slog.Any("error", err))
		}
	}()

	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}

	s.client.Client.Close()
	logger.Log.Info("Shutdown dashboard")
	if err := s.probeServer.Shutdown(ctx); err != nil {
		logger.Log.Warn("Failed shutdown the probe listener", slog.Any("error", err))
	}

	return s.server.Shutdown(ctx)
}

func (s *Server) handleReadiness(w http.ResponseWriter, _ *http.Request) {
	if !s.client.Alive() {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
}

// verifyRequest gates the endpoints that are not served through Connect. The Connect endpoints
// are covered by newAuthInterceptor instead.
func (s *Server) verifyRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token := req.Header.Get(authproxy.TokenHeaderName)
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if _, err := verifyToken(token, s.publicKey); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, req)
	})
}

// handleDownloadCert is not a Connect endpoint because the browser downloads the file through
// Content-Disposition.
func (s *Server) handleDownloadCert(w http.ResponseWriter, req *http.Request) {
	serialNumber, err := parseSerialNumber(req.URL.Query().Get("serial"))
	if err != nil {
		logger.Log.Info("Can't convert to integer", slog.String("serial", req.URL.Query().Get("serial")))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	cert, err := s.client.WithRequest(req).GetCert(req.Context(), serialNumber)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	format := "p12"
	if req.URL.Query().Get("format") == "cert" {
		format = "cert"
	}
	if format == "p12" && len(cert.P12) == 0 {
		format = "cert"
	}

	ext := "crt"
	if format == "p12" {
		ext = "p12"
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.%s", serialNumber.Text(16), ext))

	switch format {
	case "p12":
		w.Write(cert.P12)
	case "cert":
		buf := new(bytes.Buffer)
		if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate}); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(buf.Bytes())
	}
}

func (s *Server) handleDownloadCACert(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=ca.crt")

	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: s.Config.CertificateAuthority.Certificate.Raw}); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(buf.Bytes())
}
