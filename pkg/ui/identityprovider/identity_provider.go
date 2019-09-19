package identityprovider

import (
	"context"
	"io"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/session"
	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/xerrors"
)

type claims struct {
	Email    string `json:"email"`
	Verified bool   `json:"email_verified"`
}

type Server struct {
	Config *config.IdentityProvider

	database     database.UserDatabase
	sessionStore session.Store
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

func NewServer(conf *config.IdentityProvider, database database.UserDatabase, store session.Store) (*Server, error) {
	issuer := ""
	switch conf.Provider {
	case "google":
		issuer = "https://accounts.google.com"
	}
	provider, err := oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	scopes := []string{oidc.ScopeOpenID}
	if len(conf.ExtraScopes) > 0 {
		scopes = append(scopes, conf.ExtraScopes...)
	}
	oauth2Config := oauth2.Config{
		ClientID:     conf.ClientId,
		ClientSecret: conf.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  conf.RedirectUrl,
		Scopes:       scopes,
	}

	s := &Server{
		Config:       conf,
		database:     database,
		sessionStore: store,
		oauth2Config: oauth2Config,
		verifier:     provider.Verifier(&oidc.Config{ClientID: conf.ClientId}),
	}

	return s, nil
}

func (s *Server) Route(router *httprouter.Router) {
	router.GET("/auth", s.handleAuth)
	router.GET("/auth/callback", s.handleCallback)
}

func (s *Server) handleAuth(w http.ResponseWriter, req *http.Request, _params httprouter.Params) {
	if req.URL.Query().Get("from") != "" {
		sess := session.New("")
		sess.From = req.URL.Query().Get("from")
		if err := s.sessionStore.SetSession(w, sess); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, req, s.oauth2Config.AuthCodeURL(""), http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, req *http.Request, _params httprouter.Params) {
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

	user, err := s.database.Get(c.Email)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	redirectUrl := ""
	sess, err := s.sessionStore.GetSession(req)
	if err != nil {
		sess = session.New(user.Id)
	} else {
		redirectUrl = sess.From
		sess.SetId(user.Id)
	}
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
