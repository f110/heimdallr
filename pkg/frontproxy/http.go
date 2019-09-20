package frontproxy

import (
	"bytes"
	"io/ioutil"
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
	"github.com/google/go-github/v28/github"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

const (
	TokenHeaderName  = "X-Auth-Token"
	UserIdHeaderName = "X-Auth-Id"
)

var TokenExpiration = 5 * time.Minute

type HttpProxy struct {
	Config *config.Config

	reverseProxy *httputil.ReverseProxy
}

func NewHttpProxy(conf *config.Config) *HttpProxy {
	p := &HttpProxy{
		Config: conf,
		reverseProxy: &httputil.ReverseProxy{
			ErrorLog: logger.CompatibleLogger,
		},
	}
	p.reverseProxy.Director = p.director

	return p
}

func (p *HttpProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
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

func (p *HttpProxy) ServeGithubWebHook(w http.ResponseWriter, req *http.Request) {
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
