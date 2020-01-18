package dashboard

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc"
	"github.com/f110/lagrangian-proxy/pkg/rpc/rpcclient"
	"github.com/f110/lagrangian-proxy/pkg/template"
	"github.com/f110/lagrangian-proxy/tmpl/dashboard"
)

type Server struct {
	Config *config.Config

	conn   *grpc.ClientConn
	client *rpcclient.ClientWithUserToken
	loader *template.Loader
	server *http.Server
	router *httprouter.Router
}

func NewServer(config *config.Config, grpcConn *grpc.ClientConn) *Server {
	s := &Server{
		Config: config,
		conn:   grpcConn,
		loader: template.New(
			dashboard.Data,
			config.Dashboard.Template.Loader,
			config.Dashboard.Template.Dir,
			map[string]interface{}{
				"includes":     includeArray,
				"ToTimeFormat": fromUnixToTimeFormat,
			},
		),
		server: &http.Server{
			Addr: config.Dashboard.Bind,
		},
	}
	mux := httprouter.New()
	s.router = mux
	s.Get("/liveness", s.handleLiveness)
	s.Get("/readiness", s.handleReadiness)
	s.Get("/", s.handleIndex)
	s.Get("/user", s.handleUserIndex)
	s.Get("/users", s.handleUsers)
	s.Post("/user", s.handleAddUser)
	s.Get("/user/:id", s.handleGetUser)
	s.Post("/user/:id/delete", s.handleDeleteUser)
	s.Post("/user/:id/maintainer", s.handleMakeMaintainer)
	s.Post("/user/:id/admin", s.handleMakeAdmin)
	s.Get("/cert", s.handleCertIndex)
	s.Get("/cert/new", s.handleNewCert)
	s.Post("/cert/new", s.handleNewClientCert)
	s.Post("/cert/revoke", s.handleRevokeCert)
	s.Get("/cert/download", s.handleDownloadCert)
	s.Get("/cert/ca", s.handleDownloadCACert)
	s.Get("/agent", s.handleAgentIndex)
	s.Get("/agent/new", s.handleNewAgent)
	s.Post("/agent/new", s.handleAgentRegister)
	s.Get("/sa", s.handleServiceAccount)
	s.Get("/sa/new", s.handleNewServiceAccount)
	s.Post("/sa/new", s.handleCreateServiceAccount)
	s.Get("/service_account/:id/token", s.handleServiceAccountToken)
	s.Post("/service_account/:id/token", s.handleNewServiceAccountToken)
	s.server.Handler = mux

	return s
}

func (s *Server) Get(path string, handle httprouter.Handle) {
	s.router.GET(path, handle)
}

func (s *Server) Post(path string, handle httprouter.Handle) {
	s.router.POST(path, handle)
}

func (s *Server) Start() error {
	logger.Log.Info("Start dashboard", zap.String("listen", s.server.Addr))
	client := rpcclient.NewClientWithUserToken(s.conn)
	s.client = client

	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}

	s.client.Client.Close()
	logger.Log.Info("Shutdown dashboard")
	return s.server.Shutdown(ctx)
}

func (s *Server) handleLiveness(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {}

func (s *Server) handleReadiness(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	if !s.client.Alive() {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	s.RenderTemplate(w, "index.tmpl", nil)
}

func (s *Server) handleServiceAccount(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	client := s.client.WithRequest(req)

	users, err := client.ListServiceAccount()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	sort.Slice(users, func(i, j int) bool {
		return strings.Compare(users[i].Id, users[j].Id) < 0
	})

	s.RenderTemplate(w, "service_account/index.tmpl", struct {
		Accounts []*rpc.UserItem
	}{
		Accounts: users,
	})
}

func (s *Server) handleNewServiceAccount(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	s.RenderTemplate(w, "service_account/new.tmpl", nil)
}

func (s *Server) handleCreateServiceAccount(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	client := s.client.WithRequest(req)

	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err := client.NewServiceAccount(req.FormValue("id"), req.FormValue("comment"))
	if err != nil {
		logger.Log.Info("Failed create service account", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/service_account", http.StatusFound)
}

func (s *Server) handleServiceAccountToken(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	client := s.client.WithRequest(req)

	user, err := client.GetUser(params.ByName("id"), true)
	if err != nil {
		logger.Log.Info("Failed get tokens", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.RenderTemplate(w, "service_account/token.tmpl", struct {
		Id     string
		Tokens []*rpc.AccessTokenItem
	}{
		Id:     params.ByName("id"),
		Tokens: user.Tokens,
	})
}

func (s *Server) handleNewServiceAccountToken(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	client := s.client.WithRequest(req)

	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	newToken, err := client.NewToken(req.FormValue("name"), params.ByName("id"))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.RenderTemplate(w, "service_account/token_new.tmpl", struct {
		Name  string
		Token string
	}{
		Name:  newToken.Name,
		Token: newToken.Value,
	})
}

type certificate struct {
	SerialNumber string
	CommonName   string
	IssuedAt     time.Time
	RevokedAt    time.Time
	Comment      string
	DownloadUrl  string
	P12          bool
}

func (s *Server) handleCertIndex(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	client := s.client.WithRequest(req)

	signed, err := client.ListCert()
	if err != nil {
		logger.Log.Info("Can't get signed certificates", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	signedCertificates := make([]*certificate, 0, len(signed))
	for _, v := range signed {
		if v.Agent {
			continue
		}

		serialNumber := big.NewInt(0)
		serialNumber.SetBytes(v.SerialNumber)
		issuedAt, err := ptypes.Timestamp(v.IssuedAt)
		if err != nil {
			continue
		}
		signedCertificates = append(signedCertificates, &certificate{
			SerialNumber: serialNumber.Text(16),
			CommonName:   v.CommonName,
			IssuedAt:     issuedAt,
			Comment:      v.Comment,
			P12:          v.HasP12,
		})
	}

	sort.Slice(signedCertificates, func(i, j int) bool {
		return signedCertificates[i].IssuedAt.After(signedCertificates[j].IssuedAt)
	})

	revoked, err := client.ListRevokedCert()
	if err != nil {
		logger.Log.Info("Can't get revoked certificate", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sort.Slice(revoked, func(i, j int) bool {
		return revoked[i].RevokedAt.Seconds > revoked[j].RevokedAt.Seconds
	})
	revokedList := make([]*certificate, 0, len(revoked))
	for _, v := range revoked {
		if v.Agent {
			continue
		}

		serialNumber := big.NewInt(0)
		serialNumber.SetBytes(v.SerialNumber)
		issuedAt, err := ptypes.Timestamp(v.IssuedAt)
		if err != nil {
			continue
		}
		revokedAt, err := ptypes.Timestamp(v.RevokedAt)
		if err != nil {
			continue
		}
		revokedList = append(revokedList, &certificate{
			SerialNumber: serialNumber.Text(16),
			CommonName:   v.CommonName,
			IssuedAt:     issuedAt,
			RevokedAt:    revokedAt,
		})
	}

	s.RenderTemplate(w, "cert/index.tmpl", struct {
		SignedCertificates  []*certificate
		RevokedCertificates []*certificate
	}{
		SignedCertificates:  signedCertificates,
		RevokedCertificates: revokedList,
	})
}

func (s *Server) handleNewCert(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	s.RenderTemplate(w, "cert/new.tmpl", nil)
}

func (s *Server) handleNewClientCert(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	client := s.client.WithRequest(req)

	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if req.FormValue("csr") != "" {
		err := client.NewCertByCSR(req.FormValue("csr"), req.FormValue("id"))
		if err != nil {
			logger.Log.Info("Failed sign CSR", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		err := client.NewCert(req.FormValue("id"), req.FormValue("password"), req.FormValue("comment"))
		if err != nil {
			logger.Log.Info("Failed create new client certificate", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, req, "/cert", http.StatusFound)
}

func (s *Server) handleRevokeCert(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	client := s.client.WithRequest(req)

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

	err := client.RevokeCert(i)
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

func (s *Server) handleDownloadCert(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	client := s.client.WithRequest(req)

	i := &big.Int{}
	i, ok := i.SetString(req.FormValue("serial"), 16)
	if !ok {
		logger.Log.Info("Can't convert to integer", zap.String("serial", req.FormValue("serial")))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	cert, err := client.GetCert(i)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	format := "p12"
	switch req.URL.Query().Get("format") {
	case "cert":
		format = req.URL.Query().Get("format")
	}

	if format == "p12" && len(cert.P12) == 0 {
		format = "cert"
	}

	ext := "crt"
	if format == "p12" {
		ext = "p12"
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.%s", i.Text(16), ext))

	switch format {
	case "p12":
		w.Write(cert.P12)
	case "cert":
		buf := new(bytes.Buffer)
		if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate}); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(buf.Bytes())
	}
}

func (s *Server) handleDownloadCACert(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=ca.crt")
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: s.Config.General.CertificateAuthority.Certificate.Raw}); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(buf.Bytes())
}

type user struct {
	Id             string
	Role           string
	Maintainer     bool
	Admin          bool
	ServiceAccount bool
}

type roleAndUser struct {
	Role  *rpc.RoleItem
	Users []user
}

func (s *Server) handleUserIndex(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	client := s.client.WithRequest(req)

	users, err := client.ListUser("")
	if err != nil {
		logger.Log.Info("Can't get users", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	userMap := make(map[string][]*rpc.UserItem)
	for _, v := range users {
		for _, r := range v.Roles {
			if _, ok := userMap[r]; !ok {
				userMap[r] = make([]*rpc.UserItem, 0)
			}
			userMap[r] = append(userMap[r], v)
		}
	}

	roles, err := client.ListRole()
	if err != nil {
		logger.Log.Info("Can't get roles", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sortedUsers := make([]roleAndUser, 0)
	for _, v := range roles {
		if v.System {
			continue
		}

		u := make([]user, 0, len(v.Name))
		for _, k := range userMap[v.Name] {
			maintainer := false
			for _, r := range k.MaintainRoles {
				if r == v.Name {
					maintainer = true
				}
			}
			serviceAccount := false
			if k.Type == rpc.UserType_SERVICE_ACCOUNT {
				serviceAccount = true
			}
			u = append(u, user{Id: k.Id, Role: v.Name, Maintainer: maintainer, Admin: k.Admin, ServiceAccount: serviceAccount})
		}
		sort.Slice(u, func(i, j int) bool {
			return strings.Compare(u[i].Id, u[j].Id) < 0
		})
		sortedUsers = append(sortedUsers, roleAndUser{Role: v, Users: u})
	}

	s.RenderTemplate(w, "user/index.tmpl", struct {
		Roles []*rpc.RoleItem
		Users []roleAndUser
	}{
		Roles: roles,
		Users: sortedUsers,
	})
}

func (s *Server) handleUsers(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	client := s.client.WithRequest(req)

	users, err := client.ListAllUser()
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
		serviceAccount := false
		switch v.Type {
		case rpc.UserType_SERVICE_ACCOUNT:
			serviceAccount = true
		}
		userList = append(userList, user{
			Id:             v.Id,
			Admin:          v.Admin,
			ServiceAccount: serviceAccount,
		})
	}

	s.RenderTemplate(w, "user/list.tmpl", struct {
		Users []user
	}{
		Users: userList,
	})
}

func (s *Server) handleGetUser(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	client := s.client.WithRequest(req)

	id := params.ByName("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	u, err := client.GetUser(id, false)
	if err != nil {
		logger.Log.Info("User not found", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s.RenderTemplate(w, "user/show.tmpl", u)
}

func (s *Server) handleAddUser(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	client := s.client.WithRequest(req)

	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if req.FormValue("id") == "" || req.FormValue("role") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := client.AddUser(req.FormValue("id"), req.FormValue("role")); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/user", http.StatusFound)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	client := s.client.WithRequest(req)

	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err := client.DeleteUser(params.ByName("id"), req.FormValue("role")); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/user", http.StatusFound)
}

func (s *Server) handleMakeMaintainer(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	client := s.client.WithRequest(req)

	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if req.FormValue("role") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := client.UserBecomeMaintainer(params.ByName("id"), req.FormValue("role")); err != nil {
		logger.Log.Info("Failure becoming maintainer", zap.String("id", params.ByName("id")), zap.String("role", req.FormValue("role")))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/user", http.StatusFound)
}

func (s *Server) handleMakeAdmin(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	client := s.client.WithRequest(req)

	if err := client.ToggleAdmin(params.ByName("id")); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/users", http.StatusFound)
}

func (s *Server) handleAgentIndex(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	client := s.client.WithRequest(req)

	signed, err := client.ListCert()
	if err != nil {
		logger.Log.Info("Can't get signed certificates", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	signedCertificates := make([]*certificate, 0, len(signed))
	for _, v := range signed {
		if !v.Agent {
			continue
		}

		serialNumber := big.NewInt(0)
		serialNumber.SetBytes(v.SerialNumber)
		issuedAt, err := ptypes.Timestamp(v.IssuedAt)
		if err != nil {
			continue
		}
		signedCertificates = append(signedCertificates, &certificate{
			SerialNumber: serialNumber.Text(16),
			CommonName:   v.CommonName,
			IssuedAt:     issuedAt,
			Comment:      v.Comment,
			P12:          len(v.P12) > 0,
		})
	}

	sort.Slice(signedCertificates, func(i, j int) bool {
		return signedCertificates[i].IssuedAt.After(signedCertificates[j].IssuedAt)
	})

	revoked, err := client.ListRevokedCert()
	if err != nil {
		logger.Log.Info("Can't get revoked certificates", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	revokedList := make([]*certificate, 0, len(revoked))
	for _, v := range revoked {
		if !v.Agent {
			continue
		}

		serialNumber := big.NewInt(0)
		serialNumber.SetBytes(v.SerialNumber)
		issuedAt, err := ptypes.Timestamp(v.IssuedAt)
		if err != nil {
			continue
		}
		revokedAt, err := ptypes.Timestamp(v.RevokedAt)
		if err != nil {
			continue
		}
		revokedList = append(revokedList, &certificate{
			SerialNumber: serialNumber.Text(16),
			CommonName:   v.CommonName,
			IssuedAt:     issuedAt,
			RevokedAt:    revokedAt,
		})
	}
	sort.Slice(revokedList, func(i, j int) bool {
		return revokedList[i].RevokedAt.After(revokedList[j].RevokedAt)
	})

	s.RenderTemplate(w, "agent/index.tmpl", struct {
		SignedCertificates  []*certificate
		RevokedCertificates []*certificate
	}{
		SignedCertificates:  signedCertificates,
		RevokedCertificates: revokedList,
	})
}

func (s *Server) handleNewAgent(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	client := s.client.WithRequest(req)

	backends, err := client.ListAgentBackend()
	if err != nil {
		logger.Log.Info("Can't get backends from rpc server", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	names := make([]string, 0, len(backends))
	for _, v := range backends {
		names = append(names, v.Name)
	}

	s.RenderTemplate(w, "agent/new.tmpl", struct {
		Names []string
	}{
		Names: names,
	})
}

func (s *Server) handleAgentRegister(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	client := s.client.WithRequest(req)

	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if req.FormValue("csr") != "" {
		err := client.NewAgentCertByCSR(req.FormValue("csr"), req.FormValue("id"))
		if err != nil {
			logger.Log.Info("Failed sign a CSR", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		err := client.NewAgentCert(req.FormValue("id"), req.FormValue("comment"))
		if err != nil {
			logger.Log.Info("Failed create a new client certificate", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, req, "/agent", http.StatusFound)
}

func (s *Server) RenderTemplate(w http.ResponseWriter, name string, data interface{}) {
	err := s.loader.Render(w, name, data)
	if err != nil {
		logger.Log.Info("Failed render template", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func includeArray(ary []string, m string) bool {
	for _, v := range ary {
		if v == m {
			return true
		}
	}

	return false
}

func fromUnixToTimeFormat(i int64, format string) string {
	return time.Unix(i, 0).Format(format)
}
