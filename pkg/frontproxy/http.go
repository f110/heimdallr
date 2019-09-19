package frontproxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/f110/lagrangian-proxy/pkg/auth"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/session"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/xerrors"
)

const (
	TokenHeaderName  = "X-Auth-Token"
	UserIdHeaderName = "X-Auth-Id"
)

var allowCipherSuites = []uint16{
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
}

var TokenExpiration = 5 * time.Minute

type FrontendProxy struct {
	Config *config.Config
	server *http.Server

	reverseProxy *httputil.ReverseProxy
	socketProxy  *SocketProxy
}

func NewFrontendProxy(conf *config.Config) *FrontendProxy {
	s := NewSocketProxy(conf)

	p := &FrontendProxy{
		Config: conf,
		server: &http.Server{
			ErrorLog: logger.CompatibleLogger,
			TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){
				SocketProxyNextProto: s.Accept,
			},
		},
		reverseProxy: &httputil.ReverseProxy{
			ErrorLog: logger.CompatibleLogger,
		},
		socketProxy: s,
	}
	p.server.Handler = p
	p.reverseProxy.Director = p.director

	return p
}

func (p *FrontendProxy) Serve() error {
	if err := http2.ConfigureServer(p.server, nil); err != nil {
		return err
	}

	l, err := net.Listen("tcp", p.Config.FrontendProxy.Bind)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	listener := tls.NewListener(l, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: allowCipherSuites,
		Certificates: []tls.Certificate{p.Config.FrontendProxy.Certificate},
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    p.Config.General.CertificateAuthority.CertPool,
		NextProtos:   []string{SocketProxyNextProto, http2.NextProtoTLS},
	})

	logger.Log.Info("Start FrontendProxy", zap.String("listen", p.Config.FrontendProxy.Bind))
	return p.server.Serve(listener)
}

func (p *FrontendProxy) Shutdown(ctx context.Context) error {
	if p.server == nil {
		return nil
	}

	logger.Log.Info("Shutdown FrontendProxy")
	return p.server.Shutdown(ctx)
}

func (p *FrontendProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	user, err := auth.Authenticate(req)
	switch err {
	case auth.ErrSessionNotFound:
		logger.Log.Debug("Session not found")
		u := &url.URL{}
		*u = *req.URL
		u.Scheme = "https"
		u.Host = req.Host
		redirectUrl, _ := url.Parse(p.Config.IdentityProvider.AuthEndpoint)
		v := &url.Values{}
		v.Set("from", u.String())
		redirectUrl.RawQuery = v.Encode()
		http.Redirect(w, req, redirectUrl.String(), http.StatusSeeOther)
		return
	case auth.ErrUserNotFound, auth.ErrNotAllowed, auth.ErrInvalidCertificate:
		logger.Log.Debug("Unauthorized", zap.Error(err))
		w.WriteHeader(http.StatusUnauthorized)
		return
	case auth.ErrHostnameNotFound:
		logger.Log.Debug("Hostname not found", zap.String("host", req.Host))
		panic(http.ErrAbortHandler)
	}

	if user == nil {
		logger.Log.Warn("Unhandled error", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	p.setHeader(req, user)

	p.reverseProxy.ServeHTTP(w, req)
}

func (p *FrontendProxy) director(req *http.Request) {
	if backend, ok := p.Config.General.GetBackendByHost(req.Host); ok {
		q := backend.Url.RawQuery
		req.URL.Host = backend.Url.Host
		req.URL.Scheme = backend.Url.Scheme
		req.URL.Path = joinPath(backend.Url.Path, req.URL.Path)
		if q == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = q + req.URL.RawQuery
		} else {
			req.URL.RawQuery = q + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
	}
}

func (p *FrontendProxy) setHeader(req *http.Request, user *database.User) {
	claim := jwt.NewWithClaims(jwt.SigningMethodES256, &jwt.StandardClaims{
		Id:        user.Id,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(TokenExpiration).Unix(),
	})
	token, err := claim.SignedString(p.Config.FrontendProxy.SigningPrivateKey)
	if err != nil {
		logger.Log.Debug("Failed sign jwt", zap.Error(err))
		return
	}
	req.Header.Set(TokenHeaderName, token)
	req.Header.Set(UserIdHeaderName, user.Id)
	cookies := req.Cookies()
	req.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name == session.CookieName {
			continue
		}
		req.AddCookie(c)
	}

	req.Header.Set("X-Forwarded-Host", req.Host)
	req.Header.Set("X-Forwarded-Proto", "https")
}

func joinPath(base, path string) string {
	baseSuffixSlash := strings.HasSuffix(base, "/")
	addingPrefixSlash := strings.HasPrefix(path, "/")
	switch {
	case baseSuffixSlash && addingPrefixSlash:
		return base + path[1:]
	case !baseSuffixSlash && !addingPrefixSlash:
		return base + "/" + path
	}

	return base + path
}
