package frontproxy

import (
	"bytes"
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-github/v29/github"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"

	"github.com/f110/lagrangian-proxy/pkg/auth"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/connector"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc/rpcclient"
	"github.com/f110/lagrangian-proxy/pkg/session"
)

const (
	TokenHeaderName  = "X-Auth-Token"
	UserIdHeaderName = "X-Auth-Id"

	requestIdLength = 32
)

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

func newAccessLogger(conf *config.Logger) *accessLogger {
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
	config    *config.Config
	connector *connector.Server
}

func NewTransport(conf *config.Config, ct *connector.Server) *Transport {
	return &Transport{
		config:    conf,
		connector: ct,
	}
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	b, ok := t.config.General.GetBackendByHost(req.Host)
	if ok && b.Agent {
		return t.connector.RoundTrip(b, req)
	}

	return b.Transport.RoundTrip(req)
}

type HttpProxy struct {
	Config *config.Config

	client       *rpcclient.Client
	accessLogger *accessLogger
	reverseProxy *httputil.ReverseProxy
}

func NewHttpProxy(conf *config.Config, ct *connector.Server, conn *grpc.ClientConn) (*HttpProxy, error) {
	c, err := rpcclient.NewClientForInternal(conn, conf.General.InternalToken)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	p := &HttpProxy{
		Config: conf,
		reverseProxy: &httputil.ReverseProxy{
			ErrorLog:  logger.CompatibleLogger,
			Transport: NewTransport(conf, ct),
		},
		client:       c,
		accessLogger: newAccessLogger(conf.Logger),
	}
	p.reverseProxy.Director = p.director

	return p, nil
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

	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	if p.Config.FrontendProxy.ExpectCT {
		w.Header().Set("Expect-CT", "max-age=60,report-uri=\"https://"+p.Config.General.ServerName+"/ct/report\"")
	}

	user, err := auth.Authenticate(req)
	defer p.accessLog(ctx, w, req, user)

	switch err {
	case auth.ErrSessionNotFound:
		logger.Log.Debug("Session not found")
		u := &url.URL{}
		*u = *req.URL
		u.Scheme = "https"
		u.Host = req.Host
		redirectUrl, _ := url.Parse(p.Config.General.AuthEndpoint)
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

func (p *HttpProxy) ServeGithubWebHook(ctx context.Context, w http.ResponseWriter, req *http.Request) {
	backend, ok := p.Config.General.GetBackendByHost(req.Host)
	if !ok {
		panic(http.ErrAbortHandler)
	}
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
	err = github.ValidateSignature(req.Header.Get("X-Hub-Signature"), buf, p.Config.FrontendProxy.GithubWebhookSecret)
	if err != nil {
		logger.Log.Debug("Couldn't validate signature", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	p.reverseProxy.ServeHTTP(w, req)
}

func (p *HttpProxy) director(req *http.Request) {
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

func (p *HttpProxy) setHeader(req *http.Request, user *database.User) {
	req.Header.Set("X-Forwarded-Host", req.Host)
	req.Header.Set("X-Forwarded-Proto", "https")

	if user.Id == "" {
		return
	}

	token, err := p.client.SignRequest(user.Id)
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
