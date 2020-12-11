package authproxy

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/go-github/v32/github"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/auth"
	"go.f110.dev/heimdallr/pkg/auth/authn"
	"go.f110.dev/heimdallr/pkg/auth/authz"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/connector"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
	"go.f110.dev/heimdallr/pkg/session"
)

const (
	TokenHeaderName  = "X-Auth-Token"
	UserIdHeaderName = "X-Auth-Id"

	requestIdLength = 32

	slackCommonName = "platform-tls-client.slack.com"
)

var TokenExpiration = 5 * time.Minute

type AccessLog struct {
	Host      string `json:"host"`
	Protocol  string `json:"protocol"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	UserAgent string `json:"user_agent"`
	ClientIp  string `json:"client_ip"`
	AppTime   int    `json:"app_time_ms"`
	RequestId string `json:"request_id"`
	UserId    string `json:"user_id"`
}

func (a AccessLog) Fields() []zap.Field {
	return []zap.Field{
		zap.String("host", a.Host),
		zap.String("protocol", a.Protocol),
		zap.String("method", a.Method),
		zap.String("path", a.Path),
		zap.Int("status", a.Status),
		zap.String("user_agent", a.UserAgent),
		zap.String("client_ip", a.ClientIp),
		zap.Int("app_time_ms", a.AppTime),
		zap.String("request_id", a.RequestId),
		zap.String("user_id", a.UserId),
	}
}

type loggedResponseWriter struct {
	http.ResponseWriter
	http.Hijacker
	http.Flusher
	status int
}

func (w *loggedResponseWriter) WriteHeader(statusCode int) {
	w.status = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

type accessLogger struct {
	internal *zap.Logger
}

func newAccessLogger(conf *configv2.Logger) *accessLogger {
	encoding := "json"
	if conf.Encoding != "" {
		encoding = conf.Encoding
	}

	encoderConf := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "",
		NameKey:        "tag",
		CallerKey:      "",
		MessageKey:     "",
		StacktraceKey:  "",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	zapConf := zap.Config{
		Level:            zap.NewAtomicLevelAt(zapcore.InfoLevel),
		Development:      false,
		Sampling:         nil,
		Encoding:         encoding,
		EncoderConfig:    encoderConf,
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}
	l, err := zapConf.Build()
	if err != nil {
		return nil
	}
	l = l.Named("access_log")
	return &accessLogger{internal: l}
}

func (a *accessLogger) Log(l AccessLog) {
	a.internal.Info("", l.Fields()...)
}

type Transport struct {
	config    *configv2.Config
	connector *connector.Server
}

func NewTransport(conf *configv2.Config, ct *connector.Server) *Transport {
	return &Transport{
		config:    conf,
		connector: ct,
	}
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	b, ok := t.config.AccessProxy.GetBackendByHost(req.Host)
	if ok && b.Agent {
		return t.connector.RoundTrip(b, req)
	}

	return b.Transport.RoundTrip(req)
}

type HttpProxy struct {
	Config *configv2.Config

	client       *rpcclient.Client
	accessLogger *accessLogger
	reverseProxy *httputil.ReverseProxy
}

func NewHttpProxy(conf *configv2.Config, ct *connector.Server, rpcClient *rpcclient.Client) *HttpProxy {
	p := &HttpProxy{
		Config: conf,
		reverseProxy: &httputil.ReverseProxy{
			ErrorLog:  logger.CompatibleLogger,
			Transport: NewTransport(conf, ct),
		},
		client:       rpcClient,
		accessLogger: newAccessLogger(conf.Logger),
	}
	p.reverseProxy.Director = p.director

	return p
}

// ServeHTTP has responsibility to serving content to client.
// ctx should be used instead of req.Context().
func (p *HttpProxy) ServeHTTP(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	logged := &loggedResponseWriter{ResponseWriter: w}
	if h, ok := w.(http.Hijacker); ok {
		logged.Hijacker = h
	}
	if f, ok := w.(http.Flusher); ok {
		logged.Flusher = f
	}
	w = logged

	if req.TLS == nil {
		// non secure access
		backend, ok := p.Config.AccessProxy.GetBackendByHost(req.Host)
		if !ok {
			logger.Log.Debug("Hostname not found", zap.String("host", req.Host))
			panic(http.ErrAbortHandler)
		}
		if !backend.AllowHttp {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}

	user, sess, err := auth.Authenticate(ctx, req)
	defer p.accessLog(ctx, w, req, user)

	switch err {
	case auth.ErrSessionNotFound:
		logger.Log.Info("Session not found", logger.WithRequestId(ctx))
		p.redirectToIdP(w, req)
		return
	case auth.ErrUserNotFound, auth.ErrNotAllowed, auth.ErrInvalidCertificate:
		logger.Log.Info("Unauthorized", zap.Error(err), logger.WithRequestId(ctx))
		w.WriteHeader(http.StatusUnauthorized)
		return
	case auth.ErrHostnameNotFound:
		logger.Log.Info("Hostname not found", zap.String("host", req.Host), logger.WithRequestId(ctx))
		panic(http.ErrAbortHandler)
	}

	if user == nil {
		logger.Log.Warn("Unhandled error", zap.Error(err), logger.WithRequestId(ctx))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = authz.Authorization(ctx, req, user, sess)
	switch err {
	case authz.ErrSessionNotFound:
		logger.Log.Info("Session not found", logger.WithRequestId(ctx))
		p.redirectToIdP(w, req)
		return
	case authz.ErrNotAllowed:
		logger.Log.Info("Unauthorized", zap.Error(err), logger.WithRequestId(ctx))
		w.WriteHeader(http.StatusUnauthorized)
		return
	case authz.ErrHostnameNotFound:
		logger.Log.Info("Hostname not found", zap.String("host", req.Host), logger.WithRequestId(ctx))
		panic(http.ErrAbortHandler)
	}

	if err := p.setHeader(req, user); err != nil {
		logger.Log.Warn("Failed to set headers to request of backend", zap.Error(err), logger.WithRequestId(ctx))
		return
	}
	p.reverseProxy.ServeHTTP(w, req)

	if logged.status >= 200 && logged.status <= 299 && req.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if p.Config.AccessProxy.HTTP.ExpectCT {
			w.Header().Set("Expect-CT", "max-age=60,report-uri=\"https://"+p.Config.AccessProxy.HTTP.ServerName+"/ct/report\"")
		}
	}
}

func (p *HttpProxy) redirectToIdP(w http.ResponseWriter, req *http.Request) {
	u := &url.URL{}
	*u = *req.URL
	u.Scheme = "https"
	u.Host = req.Host
	redirectUrl, _ := url.Parse(p.Config.AccessProxy.AuthEndpoint)
	v := &url.Values{}
	v.Set("from", u.String())
	redirectUrl.RawQuery = v.Encode()
	http.Redirect(w, req, redirectUrl.String(), http.StatusSeeOther)
}

func (p *HttpProxy) ServeGithubWebHook(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	backend, ok := p.Config.AccessProxy.GetBackendByHost(req.Host)
	if !ok {
		panic(http.ErrAbortHandler)
	}

	w = &loggedResponseWriter{ResponseWriter: w}
	defer p.accessLog(ctx, w, req, &database.User{})

	if backend.WebHook != "github" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	ok = backend.WebHookRouter.Match(req, &mux.RouteMatch{})
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	buf, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return
	}
	req.Body.Close()
	req.Body = ioutil.NopCloser(bytes.NewReader(buf))
	err = github.ValidateSignature(req.Header.Get("X-Hub-Signature"), buf, p.Config.AccessProxy.Credential.GithubWebhookSecret)
	if err != nil {
		logger.Log.Debug("Couldn't validate signature", zap.Error(err), logger.WithRequestId(ctx))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	p.reverseProxy.ServeHTTP(w, req)
}

func (p *HttpProxy) ServeSlackWebHook(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	backend, ok := p.Config.AccessProxy.GetBackendByHost(req.Host)
	if !ok {
		panic(http.ErrAbortHandler)
	}

	w = &loggedResponseWriter{ResponseWriter: w}
	defer p.accessLog(ctx, w, req, &database.User{})

	if backend.WebHook != "slack" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	ok = backend.WebHookRouter.Match(req, &mux.RouteMatch{})
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// We verify the client by client certificate.
	if req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		logger.Log.Info("The client does not submit any certificate", logger.WithRequestId(ctx))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	found := false
	for _, v := range req.TLS.PeerCertificates {
		if v.Subject.CommonName == slackCommonName {
			found = true
			break
		}
	}
	if !found {
		logger.Log.Info("Slack's Common name could not be found in client certificates", logger.WithRequestId(ctx))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	p.reverseProxy.ServeHTTP(w, req)
}

func (p *HttpProxy) director(req *http.Request) {
	if backend, ok := p.Config.AccessProxy.GetBackendByHost(req.Host); ok {
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
		logger.Log.Debug("Backend is ", zap.String("url", req.URL.String()), zap.String("name", backend.Name))
	}
}

func (p *HttpProxy) setHeader(req *http.Request, user *database.User) error {
	req.Header.Set("X-Forwarded-Host", req.Host)
	req.Header.Set("X-Forwarded-Proto", "https")

	if user.Id != "" {
		claim := jwt.NewWithClaims(jwt.SigningMethodES256, &authn.TokenClaims{
			StandardClaims: jwt.StandardClaims{
				Id:        user.Id,
				IssuedAt:  time.Now().Unix(),
				ExpiresAt: time.Now().Add(TokenExpiration).Unix(),
			},
			Roles: user.Roles,
		})
		token, err := claim.SignedString(p.Config.AccessProxy.Credential.SigningPrivateKey)
		if err != nil {
			logger.Log.Warn("Failed sign jwt", zap.Error(err))
			return xerrors.Errorf(": %w", err)
		}

		req.Header.Set(TokenHeaderName, token)
		req.Header.Set(UserIdHeaderName, user.Id)
	}

	cookies := req.Cookies()
	req.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name == session.CookieName {
			continue
		}
		req.AddCookie(c)
	}

	return nil
}

func (p *HttpProxy) accessLog(ctx context.Context, w http.ResponseWriter, req *http.Request, user *database.User) {
	requestId := ""
	v := ctx.Value("request_id")
	if v != nil {
		switch s := v.(type) {
		case string:
			requestId = s
		}
	}

	status := 0
	switch v := w.(type) {
	case *loggedResponseWriter:
		status = v.status
	}

	appTime := 0
	v = ctx.Value("dispatch_time")
	if v != nil {
		switch s := v.(type) {
		case time.Time:
			appTime = int(time.Now().Sub(s).Milliseconds())
		}
	}
	remoteAddr := strings.Split(req.RemoteAddr, ":")
	id := ""
	if user != nil {
		id = user.Id
	}

	l := AccessLog{
		Host:      req.Host,
		Protocol:  req.Proto,
		Method:    req.Method,
		Path:      req.URL.Path,
		Status:    status,
		UserAgent: req.Header.Get("User-Agent"),
		ClientIp:  remoteAddr[0],
		AppTime:   appTime,
		RequestId: requestId,
		UserId:    id,
	}
	p.accessLogger.Log(l)
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
