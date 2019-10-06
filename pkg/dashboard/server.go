package dashboard

import (
	"context"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/database/etcd"
	"github.com/f110/lagrangian-proxy/pkg/frontproxy"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/template"
	"github.com/f110/lagrangian-proxy/tmpl/dashboard"
	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

type Server struct {
	Config       *config.Config
	loader       *template.Loader
	server       *http.Server
	userDatabase *etcd.UserDatabase
	ca           database.CertificateAuthority
	router       *httprouter.Router
}

func NewServer(config *config.Config, userDatabase *etcd.UserDatabase, ca database.CertificateAuthority) *Server {
	s := &Server{
		userDatabase: userDatabase,
		ca:           ca,
		Config:       config,
		loader:       template.New(dashboard.Data, config.Dashboard.Template.Loader, config.Dashboard.Template.Dir),
		server: &http.Server{
			Addr: config.Dashboard.Bind,
		},
	}
	mux := httprouter.New()
	s.router = mux
	s.Get("/", s.handleIndex)
	s.Get("/user", s.handleUserIndex, s.AdminOnly)
	s.Get("/users", s.handleUsers, s.AdminOnly)
	s.Post("/user", s.handleAddUser, s.AdminOnly)
	s.Get("/user/:id", s.handleGetUser, s.AdminOnly)
	s.Post("/user/:id/delete", s.handleDeleteUser, s.AdminOnly)
	s.Post("/user/:id/maintainer", s.handleMakeMaintainer, s.AdminOnly)
	s.Post("/user/:id/admin", s.handleMakeAdmin, s.AdminOnly)
	s.Get("/cert", s.handleCertIndex, s.AdminOnly)
	s.Get("/cert/new", s.handleNewCert, s.AdminOnly)
	s.Post("/cert/new", s.handleNewClientCert, s.AdminOnly)
	s.Post("/cert/revoke", s.handleRevokeCert, s.AdminOnly)
	s.Get("/cert/download", s.handleDownloadCert, s.AdminOnly)
	s.Get("/agent", s.handleAgentIndex, s.AdminOnly)
	s.Get("/agent/new", s.handleNewAgent, s.AdminOnly)
	s.Post("/agent/new", s.handleAgentRegister, s.AdminOnly)
	s.server.Handler = mux

	return s
}

type filterFunc func(w http.ResponseWriter, req *http.Request) (*database.User, error)
type handleFunc func(user *database.User, w http.ResponseWriter, req *http.Request, params httprouter.Params)

func (s *Server) Get(path string, handle handleFunc, filter ...filterFunc) {
	s.method(s.router.GET, path, handle, filter...)
}

func (s *Server) Post(path string, handle handleFunc, filter ...filterFunc) {
	s.method(s.router.POST, path, handle, filter...)
}

func (s *Server) method(method func(string, httprouter.Handle), path string, handle handleFunc, filter ...filterFunc) {
	method(path, func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		var user *database.User
		if len(filter) > 0 {
			u, err := filter[0](w, req)
			if err != nil {
				logger.Log.Debug("Unauthorized", zap.Error(err))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			user = u
		}
		handle(user, w, req, params)
	})
}

func (s *Server) AdminOnly(w http.ResponseWriter, req *http.Request) (*database.User, error) {
	h := req.Header.Get(frontproxy.TokenHeaderName)
	if h == "" {
		return nil, xerrors.New("dashboard: token header not found")
	}

	claims := &jwt.StandardClaims{}
	_, err := jwt.ParseWithClaims(h, claims, func(token *jwt.Token) (i interface{}, e error) {
		if token.Method != jwt.SigningMethodES256 {
			return nil, xerrors.New("dashboard: invalid signing method")
		}
		return &s.Config.FrontendProxy.SigningPublicKey, nil
	})
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	if err := claims.Valid(); err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	user, err := s.userDatabase.Get(claims.Id)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	if user.Admin {
		return user, nil
	}
	for _, v := range s.Config.General.RootUsers {
		if v == user.Id {
			return user, nil
		}
	}

	return nil, xerrors.New("dashboard: user is not admin")
}

func (s *Server) Start() error {
	logger.Log.Info("Start dashboard", zap.String("listen", s.server.Addr))
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}

	logger.Log.Info("Shutdown dashboard")
	return s.server.Shutdown(ctx)
}

func (s *Server) handleIndex(_ *database.User, w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	s.RenderTemplate(w, "index.tmpl", nil)
}

type signedCertificate struct {
	SerialNumber string
	CommonName   string
	IssuedAt     time.Time
	Comment      string
	DownloadUrl  string
	P12          bool
}

func (s *Server) handleCertIndex(_ *database.User, w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	signed, err := s.ca.GetSignedCertificates(req.Context())
	if err != nil {
		logger.Log.Info("Can't get signed certificates", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	signedCertificates := make([]*signedCertificate, 0, len(signed))
	for _, v := range signed {
		if v.Agent {
			continue
		}
		signedCertificates = append(signedCertificates, &signedCertificate{
			SerialNumber: v.Certificate.SerialNumber.Text(16),
			CommonName:   v.Certificate.Subject.CommonName,
			IssuedAt:     v.IssuedAt,
			Comment:      v.Comment,
			P12:          len(v.P12) > 0,
		})
	}

	sort.Slice(signedCertificates, func(i, j int) bool {
		return signedCertificates[i].IssuedAt.After(signedCertificates[j].IssuedAt)
	})

	revoked := s.ca.GetRevokedCertificates()
	sort.Slice(revoked, func(i, j int) bool {
		return revoked[i].RevokedAt.After(revoked[j].RevokedAt)
	})
	revokedList := make([]*database.RevokedCertificate, 0, len(revoked))
	for _, v := range revoked {
		if v.Agent {
			continue
		}
		revokedList = append(revokedList, v)
	}

	s.RenderTemplate(w, "cert/index.tmpl", struct {
		CertificateAuthority *x509.Certificate
		SignedCertificates   []*signedCertificate
		RevokedCertificates  []*database.RevokedCertificate
	}{
		CertificateAuthority: s.Config.General.CertificateAuthority.Certificate,
		SignedCertificates:   signedCertificates,
		RevokedCertificates:  revokedList,
	})
}

func (s *Server) handleNewCert(_ *database.User, w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	s.RenderTemplate(w, "cert/new.tmpl", nil)
}

func (s *Server) handleNewClientCert(_ *database.User, w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err := s.ca.NewClientCertificate(req.Context(), req.FormValue("id"), req.FormValue("password"), req.FormValue("comment"))
	if err != nil {
		logger.Log.Info("Failed create new client certificate", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/cert", http.StatusFound)
}

func (s *Server) handleRevokeCert(_ *database.User, w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	i := &big.Int{}
	i, ok := i.SetString(req.FormValue("serial"), 16)
	if !ok {
		logger.Log.Info("Can't convert to integer", zap.String("serial", req.FormValue("serial")))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	signedCertificate, err := s.ca.GetSignedCertificate(req.Context(), i)
	if err != nil {
		logger.Log.Info("Can't get signed certificate", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = s.ca.Revoke(req.Context(), signedCertificate)
	if err != nil {
		logger.Log.Info("Failed revoke certificate", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if _, ok := req.Form["agent"]; ok {
		http.Redirect(w, req, "/agent", http.StatusFound)
	} else {
		http.Redirect(w, req, "/cert", http.StatusFound)
	}
}

func (s *Server) handleDownloadCert(_ *database.User, w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	i := &big.Int{}
	i, ok := i.SetString(req.FormValue("serial"), 16)
	if !ok {
		logger.Log.Info("Can't convert to integer", zap.String("serial", req.FormValue("serial")))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	certificate, err := s.ca.GetSignedCertificate(req.Context(), i)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ext := "crt"
	if len(certificate.P12) > 0 {
		ext = "p12"
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.%s", certificate.Certificate.SerialNumber.Text(16), ext))
	if len(certificate.P12) > 0 {
		w.Write(certificate.P12)
	} else {
		w.Write(certificate.Certificate.Raw)
	}
}

type user struct {
	Id         string
	Role       string
	Maintainer bool
	Admin      bool
}

type roleAndUser struct {
	Role  config.Role
	Users []user
}

func (s *Server) handleUserIndex(_ *database.User, w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	users, err := s.userDatabase.GetAll()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	userMap := make(map[string][]*database.User)
	for _, v := range users {
		for _, r := range v.Roles {
			if _, ok := userMap[r]; !ok {
				userMap[r] = make([]*database.User, 0)
			}
			userMap[r] = append(userMap[r], v)
		}
	}

	sortedUsers := make([]roleAndUser, 0)
	for _, v := range s.Config.General.GetAllRoles() {
		u := make([]user, 0, len(v.Name))
		for _, k := range userMap[v.Name] {
			maintainer := false
			if v, ok := k.MaintainRoles[v.Name]; ok {
				maintainer = v
			}
			u = append(u, user{Id: k.Id, Role: v.Name, Maintainer: maintainer, Admin: k.Admin})
		}
		sort.Slice(u, func(i, j int) bool {
			return strings.Compare(u[i].Id, u[j].Id) < 0
		})
		sortedUsers = append(sortedUsers, roleAndUser{Role: v, Users: u})
	}

	s.RenderTemplate(w, "user/index.tmpl", struct {
		Roles []config.Role
		Users []roleAndUser
	}{
		Roles: s.Config.General.GetAllRoles(),
		Users: sortedUsers,
	})
}

func (s *Server) handleUsers(_ *database.User, w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	users, err := s.userDatabase.GetAll()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	sort.Slice(users, func(i, j int) bool {
		if users[i].Admin == users[j].Admin {
			return strings.Compare(users[i].Id, users[j].Id) < 0
		}
		return users[i].Admin == true
	})

	userList := make([]user, 0, len(users))
	for _, v := range users {
		userList = append(userList, user{
			Id:    v.Id,
			Admin: v.Admin,
		})
	}

	s.RenderTemplate(w, "user/list.tmpl", struct {
		Users []user
	}{
		Users: userList,
	})
}

func (s *Server) handleGetUser(_ *database.User, w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	id := params.ByName("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	u, err := s.userDatabase.Get(id)
	if err != nil {
		logger.Log.Info("User not found", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.RenderTemplate(w, "user/show.tmpl", u)
}

func (s *Server) handleAddUser(_ *database.User, w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if req.FormValue("id") == "" || req.FormValue("role") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	u, err := s.userDatabase.Get(req.FormValue("id"))
	if err != nil && err != database.ErrUserNotFound {
		logger.Log.Info("Failure get user", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if u != nil {
		u.Roles = append(u.Roles, req.FormValue("role"))
	} else {
		u = &database.User{Id: req.FormValue("id"), Roles: []string{req.FormValue("role")}}
	}

	if err := s.userDatabase.Set(req.Context(), u); err != nil {
		logger.Log.Warn("Failure create or update user", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/user", http.StatusFound)
}

func (s *Server) handleDeleteUser(_ *database.User, w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	u, err := s.userDatabase.Get(params.ByName("id"))
	if err != nil {
		logger.Log.Info("Failure get user", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if req.FormValue("role") == "" {
		if err := s.userDatabase.Delete(req.Context(), u.Id); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.Redirect(w, req, "/users", http.StatusFound)
		return
	}

	for i := range u.Roles {
		if u.Roles[i] == req.FormValue("role") {
			u.Roles = append(u.Roles[:i], u.Roles[i+1:]...)
			break
		}
	}

	if err := s.userDatabase.Set(req.Context(), u); err != nil {
		logger.Log.Warn("Failure delete role", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/user", http.StatusFound)
}

func (s *Server) handleMakeMaintainer(_ *database.User, w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if req.FormValue("role") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	u, err := s.userDatabase.Get(params.ByName("id"))
	if err != nil {
		logger.Log.Info("Failure get user", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	u.MaintainRoles[req.FormValue("role")] = true

	if err := s.userDatabase.Set(req.Context(), u); err != nil {
		logger.Log.Warn("Failure update user", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/user", http.StatusFound)
}

func (s *Server) handleMakeAdmin(_ *database.User, w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	u, err := s.userDatabase.Get(params.ByName("id"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	u.Admin = !u.Admin

	if err := s.userDatabase.Set(req.Context(), u); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/users", http.StatusFound)
}

func (s *Server) handleAgentIndex(_ *database.User, w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	signed, err := s.ca.GetSignedCertificates(req.Context())
	if err != nil {
		logger.Log.Info("Can't get signed certificates", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	signedCertificates := make([]*signedCertificate, 0, len(signed))
	for _, v := range signed {
		if !v.Agent {
			continue
		}
		signedCertificates = append(signedCertificates, &signedCertificate{
			SerialNumber: v.Certificate.SerialNumber.Text(16),
			CommonName:   v.Certificate.Subject.CommonName,
			IssuedAt:     v.IssuedAt,
			Comment:      v.Comment,
			P12:          len(v.P12) > 0,
		})
	}

	sort.Slice(signedCertificates, func(i, j int) bool {
		return signedCertificates[i].IssuedAt.After(signedCertificates[j].IssuedAt)
	})

	revoked := s.ca.GetRevokedCertificates()
	revokedList := make([]*database.RevokedCertificate, 0, len(revoked))
	for _, v := range revoked {
		if !v.Agent {
			continue
		}
		revokedList = append(revokedList, v)
	}
	sort.Slice(revokedList, func(i, j int) bool {
		return revokedList[i].RevokedAt.After(revokedList[j].RevokedAt)
	})

	s.RenderTemplate(w, "agent/index.tmpl", struct {
		SignedCertificates  []*signedCertificate
		RevokedCertificates []*database.RevokedCertificate
	}{
		SignedCertificates:  signedCertificates,
		RevokedCertificates: revokedList,
	})
}

func (s *Server) handleNewAgent(_ *database.User, w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	backends := s.Config.General.GetAllBackends()
	names := make([]string, 0, len(backends))
	for _, v := range backends {
		if !v.Agent {
			continue
		}
		names = append(names, v.Name)
	}

	s.RenderTemplate(w, "agent/new.tmpl", struct {
		Names []string
	}{
		Names: names,
	})
}

func (s *Server) handleAgentRegister(_ *database.User, w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	backend, ok := s.Config.General.GetBackend(req.FormValue("id"))
	if !ok || !backend.Agent {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	_, err := s.ca.NewAgentCertificate(req.Context(), req.FormValue("id"), req.FormValue("comment"))
	if err != nil {
		logger.Log.Info("Failed create new client certificate", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/agent", http.StatusFound)
}

func (s *Server) RenderTemplate(w http.ResponseWriter, name string, data interface{}) {
	err := s.loader.Render(w, name, data)
	if err != nil {
		logger.Log.Debug("Failed render template", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
	}
}
