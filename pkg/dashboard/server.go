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

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/database/etcd"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/template"
	"github.com/f110/lagrangian-proxy/tmpl/dashboard"
	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"
)

type Server struct {
	config       *config.Config
	loader       *template.Loader
	server       *http.Server
	userDatabase *etcd.UserDatabase
	ca           database.CertificateAuthority
}

func NewServer(config *config.Config, userDatabase *etcd.UserDatabase, ca database.CertificateAuthority) *Server {
	s := &Server{
		userDatabase: userDatabase,
		ca:           ca,
		config:       config,
		loader:       template.New(dashboard.Data, config.Dashboard.Template.Loader, config.Dashboard.Template.Dir),
		server: &http.Server{
			Addr: config.Dashboard.Bind,
		},
	}
	mux := httprouter.New()
	mux.GET("/", s.handleIndex)
	mux.GET("/user", s.handleUserIndex)
	mux.POST("/user", s.handleAddUser)
	mux.GET("/user/:id", s.handleGetUser)
	mux.POST("/user/:id/delete", s.handleDeleteUser)
	mux.POST("/user/:id/maintainer", s.handleMakeMaintainer)
	mux.GET("/cert", s.handleCertIndex)
	mux.GET("/cert/new", s.handleNewCert)
	mux.POST("/cert/new", s.handleNewClientCert)
	mux.POST("/cert/revoke", s.handleRevokeCert)
	mux.GET("/cert/download", s.handleDownloadCert)
	s.server.Handler = mux

	return s
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

func (s *Server) handleIndex(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
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

func (s *Server) handleCertIndex(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	signed, err := s.ca.GetSignedCertificates(req.Context())
	if err != nil {
		logger.Log.Info("Can't get signed certificates", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	signedCertificates := make([]*signedCertificate, 0, len(signed))
	for _, v := range signed {
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

	revoked, err := s.ca.GetRevokedCertificates(req.Context())
	if err != nil {
		logger.Log.Info("Can't get revoked certificates", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sort.Slice(revoked, func(i, j int) bool {
		return revoked[i].RevokedAt.After(revoked[j].RevokedAt)
	})

	s.RenderTemplate(w, "cert/index.tmpl", struct {
		CertificateAuthority *x509.Certificate
		SignedCertificates   []*signedCertificate
		RevokedCertificates  []*database.RevokedCertificate
	}{
		CertificateAuthority: s.config.General.CertificateAuthority.Certificate,
		SignedCertificates:   signedCertificates,
		RevokedCertificates:  revoked,
	})
}

func (s *Server) handleNewCert(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	s.RenderTemplate(w, "cert/new.tmpl", nil)
}

func (s *Server) handleNewClientCert(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
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

func (s *Server) handleRevokeCert(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
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

	http.Redirect(w, req, "/cert", http.StatusFound)
}

func (s *Server) handleDownloadCert(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
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
}

type roleAndUser struct {
	Role  config.Role
	Users []user
}

func (s *Server) handleUserIndex(w http.ResponseWriter, req *http.Request, _params httprouter.Params) {
	users, err := s.userDatabase.GetAll(req.Context())
	if err != nil {
		logger.Log.Info("Failed fetch user list", zap.Error(err))
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
	for _, v := range s.config.General.GetAllRoles() {
		u := make([]user, 0, len(v.Name))
		for _, k := range userMap[v.Name] {
			maintainer := false
			if v, ok := k.MaintainRoles[v.Name]; ok {
				maintainer = v
			}
			u = append(u, user{Id: k.Id, Role: v.Name, Maintainer: maintainer})
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
		Roles: s.config.General.GetAllRoles(),
		Users: sortedUsers,
	})
}

func (s *Server) handleGetUser(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	id := params.ByName("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	u, err := s.userDatabase.Get(req.Context(), id)
	if err != nil {
		logger.Log.Info("User not found", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.RenderTemplate(w, "user/show.tmpl", u)
}

func (s *Server) handleAddUser(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if req.FormValue("id") == "" || req.FormValue("role") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	u, err := s.userDatabase.Get(req.Context(), req.FormValue("id"))
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

func (s *Server) handleDeleteUser(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if req.FormValue("role") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	u, err := s.userDatabase.Get(req.Context(), params.ByName("id"))
	if err != nil {
		logger.Log.Info("Failure get user", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
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

func (s *Server) handleMakeMaintainer(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if req.FormValue("role") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	u, err := s.userDatabase.Get(req.Context(), params.ByName("id"))
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

func (s *Server) RenderTemplate(w http.ResponseWriter, name string, data interface{}) {
	err := s.loader.Render(w, name, data)
	if err != nil {
		logger.Log.Debug("Failed render template", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
	}
}
