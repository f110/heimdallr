package identityprovider

import (
	"context"
	"io"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/server"
	"go.f110.dev/heimdallr/pkg/session"
)

type claims struct {
	Email    string `json:"email"`
	Verified bool   `json:"email_verified"`
}

type Server struct {
	Config *config.Config

	database     database.UserDatabase
	sessionStore session.Store
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

var _ server.ChildServer = &Server{}

func NewServer(conf *config.Config, database database.UserDatabase, store session.Store) (*Server, error) {
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
	provider, err := oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	scopes := []string{oidc.ScopeOpenID}
	if len(conf.IdentityProvider.ExtraScopes) > 0 {
		scopes = append(scopes, conf.IdentityProvider.ExtraScopes...)
	}
	oauth2Config := oauth2.Config{
		ClientID:     conf.IdentityProvider.ClientId,
		ClientSecret: conf.IdentityProvider.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  conf.IdentityProvider.RedirectUrl,
		Scopes:       scopes,
	}

	s := &Server{
		Config:       conf,
		database:     database,
		sessionStore: store,
		oauth2Config: oauth2Config,
		verifier:     provider.Verifier(&oidc.Config{ClientID: conf.IdentityProvider.ClientId}),
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
	idToken, err := s.verifier.Verify(req.Context(), rawIdToken)
	if err != nil {
		logger.Log.Info("Not verified id token", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	c := &claims{}
	if err := idToken.Claims(c); err != nil {
		logger.Log.Info("Failed extract claims", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if c.Email == "" {
		logger.Log.Info("Could not get email address. Probably, you should set more scope.")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	rootUser := false
	for _, v := range s.Config.General.RootUsers {
		if v == c.Email {
			rootUser = true
			break
		}
	}

	_, err = s.database.Get(c.Email)
	if err != nil && !rootUser {
		logger.Log.Info("Could not get email", zap.Error(err))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	redirectUrl := ""
	if sess.From != "" {
		redirectUrl = sess.From
	}
	sess.SetId(c.Email)
	if err := s.sessionStore.SetSession(w, sess); err != nil {
		logger.Log.Info("Failed write session", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if redirectUrl != "" {
		logger.Log.Debug("Redirect to", zap.String("url", redirectUrl))
		http.Redirect(w, req, redirectUrl, http.StatusFound)
	} else {
		io.WriteString(w, "success!")
	}
}
