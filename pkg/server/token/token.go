package token

import (
	"encoding/json"
	"net/http"

	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/localproxy"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/server"
	"github.com/f110/lagrangian-proxy/pkg/session"
	"github.com/f110/lagrangian-proxy/pkg/template"
	"github.com/f110/lagrangian-proxy/tmpl/ui"
	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"
)

type Server struct {
	loader        *template.Loader
	sessionStore  session.Store
	tokenDatabase database.TokenDatabase
}

var _ server.ChildServer = &Server{}

func New(sessionStore session.Store, tokenDatabase database.TokenDatabase) *Server {
	return &Server{
		loader:        template.New(ui.Data, template.LoaderTypeEmbed, "tmpl/ui/token"),
		sessionStore:  sessionStore,
		tokenDatabase: tokenDatabase,
	}
}

func (t *Server) Route(router *httprouter.Router) {
	router.GET("/token/authorize", t.handle)            // for browser
	router.GET("/token/authorized", t.handleAuthorized) // for browser
	router.GET("/token/exchange", t.handleExchange)     // for api
}

func (t *Server) handle(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	sess, err := t.sessionStore.GetSession(req)
	if err != nil {
		logger.Log.Debug("session not found")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	sess.Challenge = req.URL.Query().Get("challenge")
	sess.ChallengeMethod = req.URL.Query().Get("challenge_method")
	if err := t.sessionStore.SetSession(w, sess); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := t.loader.Render(w, "authorization.tmpl", nil); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (t *Server) handleAuthorized(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	sess, err := t.sessionStore.GetSession(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	code, err := t.tokenDatabase.NewCode(req.Context(), sess.Id, sess.Challenge, sess.ChallengeMethod)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.Redirect(w, req, localproxy.ClientRedirectUrl+"?code="+code.Code, http.StatusFound)
}

func (t *Server) handleExchange(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	token, err := t.tokenDatabase.IssueToken(req.Context(), req.URL.Query().Get("code"), req.URL.Query().Get("code_verifier"))
	if err != nil {
		logger.Log.Debug("Failure issue token", zap.Error(err), zap.String("code", req.URL.Query().Get("code")))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	res := &localproxy.TokenExchangeResponse{
		AccessToken: token.Token,
		ExpiresIn:   int(database.TokenExpiration.Seconds()),
	}
	if err := json.NewEncoder(w).Encode(res); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
