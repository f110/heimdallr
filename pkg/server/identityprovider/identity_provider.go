package identityprovider

import (
	"io"
	"net/http"
	"time"

	"github.com/caos/oidc/pkg/client/rp"
	"github.com/caos/oidc/pkg/oidc"
	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/server"
	"go.f110.dev/heimdallr/pkg/session"
)

type Server struct {
	Config *configv2.Config

	database        database.UserDatabase
	sessionStore    session.Store
	oauth2Config    oauth2.Config
	idTokenVerifier rp.IDTokenVerifier
}

var _ server.ChildServer = &Server{}

func NewServer(conf *configv2.Config, database database.UserDatabase, store session.Store) (*Server, error) {
	issuer := ""
	switch conf.IdentityProvider.Provider {
	case "google":
		issuer = "https://accounts.google.com"
	case "okta":
		issuer = "https://" + conf.IdentityProvider.Domain + ".okta.com"
	case "azure":
		issuer = "https://login.microsoftonline.com/" + conf.IdentityProvider.Domain + "/v2.0"
	case "custom":
		issuer = conf.IdentityProvider.Issuer
	default:
		return nil, xerrors.Errorf("unknown provider: %s", conf.IdentityProvider.Provider)
	}

	scopes := []string{oidc.ScopeOpenID}
	if len(conf.IdentityProvider.ExtraScopes) > 0 {
		scopes = append(scopes, conf.IdentityProvider.ExtraScopes...)
	}

	relyingParty, err := rp.NewRelyingPartyOIDC(
		issuer,
		conf.IdentityProvider.ClientId,
		conf.IdentityProvider.ClientSecret,
		conf.IdentityProvider.RedirectUrl,
		scopes,
	)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	s := &Server{
		Config:          conf,
		database:        database,
		sessionStore:    store,
		oauth2Config:    *relyingParty.OAuthConfig(),
		idTokenVerifier: relyingParty.IDTokenVerifier(),
	}

	return s, nil
}

func (s *Server) Route(router *httprouter.Router) {
	router.GET("/auth", s.handleAuth)
	router.GET("/auth/callback", s.handleCallback)
}

func (s *Server) handleAuth(w http.ResponseWriter, req *http.Request, _params httprouter.Params) {
	sess := session.New("")
	if req.URL.Query().Get("from") != "" {
		sess.From = req.URL.Query().Get("from")

	}
	state, err := s.database.SetState(req.Context(), sess.Unique)
	if err != nil {
		logger.Log.Info("Failed set state", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logger.Log.Debug("Generated state", zap.String("value", state))
	if err := s.sessionStore.SetSession(w, sess); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.Redirect(w, req, s.oauth2Config.AuthCodeURL(state), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, req *http.Request, _params httprouter.Params) {
	sess, err := s.sessionStore.GetSession(req)
	if err != nil {
		logger.Log.Debug("Could not get session", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	unique, err := s.database.GetState(req.Context(), req.URL.Query().Get("state"))
	if err != nil {
		logger.Log.Debug("Could not get state", zap.Error(err), zap.String("state", req.URL.Query().Get("state")))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if sess.Unique != unique {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	token, err := s.oauth2Config.Exchange(req.Context(), req.URL.Query().Get("code"))
	if err != nil {
		logger.Log.Info("Failed exchange token", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	rawIdToken, ok := token.Extra("id_token").(string)
	if !ok {
		logger.Log.Info("Failed covert token to raw id token")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logger.Log.Debug("raw_id_token", zap.String("token", rawIdToken))
	idToken, err := rp.VerifyIDToken(req.Context(), rawIdToken, s.idTokenVerifier)
	if err != nil {
		logger.Log.Info("Not verified id token", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if idToken.GetEmail() == "" {
		logger.Log.Info("Could not get email address. Probably, you should set more scope.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	rootUser := false
	for _, v := range s.Config.AuthorizationEngine.RootUsers {
		if v == idToken.GetEmail() {
			rootUser = true
			break
		}
	}

	user, err := s.database.Get(idToken.GetEmail())
	if err != nil && !rootUser {
		logger.Log.Info("Could not get email", zap.Error(err))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	redirectUrl := ""
	if sess.From != "" {
		redirectUrl = sess.From
	}
	sess.SetId(idToken.GetEmail())
	if err := s.sessionStore.SetSession(w, sess); err != nil {
		logger.Log.Info("Failed write session", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if user != nil {
		user.LastLogin = time.Now()
		if err := s.database.Set(req.Context(), user); err != nil {
			logger.Log.Warn("Failed update user", zap.Error(err), zap.String("id", user.Id))
		}
	}

	if redirectUrl != "" {
		logger.Log.Debug("Redirect to", zap.String("url", redirectUrl))
		http.Redirect(w, req, redirectUrl, http.StatusFound)
	} else {
		io.WriteString(w, "success!")
	}
}
