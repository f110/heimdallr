package dashboard

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/protobuf/ptypes"
	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"

	"go.f110.dev/heimdallr/pkg/auth/authn"
	"go.f110.dev/heimdallr/pkg/authproxy"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/rpc"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
	"go.f110.dev/heimdallr/pkg/template"
	"go.f110.dev/heimdallr/tmpl/dashboard"
)

type Server struct {
	Config *configv2.Config

	publicKey crypto.PublicKey
	conn      *grpc.ClientConn
	client    *rpcclient.ClientWithUserToken
	loader    *template.Loader
	server    *http.Server
	router    *httprouter.Router
}

func NewServer(config *configv2.Config, grpcConn *grpc.ClientConn) (*Server, error) {
	req, err := http.NewRequest(http.MethodGet, config.Dashboard.PublicKeyUrl, nil)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	res.Body.Close()
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, xerrors.New("failed parse public key")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, xerrors.Errorf("unexpected type: %s", block.Type)
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	s := &Server{
		Config:    config,
		publicKey: publicKey,
		conn:      grpcConn,
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
	// Probe endpoints should not verify a JWT header.
	mux.GET("/liveness", s.handleLiveness)
	mux.GET("/readiness", s.handleReadiness)
	s.Get("/role", s.handleRoleIndex)
	s.Get("/user", s.handleUsers)
	s.Post("/user", s.handleAddUser)
	s.Get("/user/:id", s.handleGetUser)
	s.Get("/user/:id/edit", s.handleEditUserIndex)
	s.Post("/user/:id/edit", s.handleEditUser)
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
	s.Get("/me", s.handleMe)
	s.Post("/me", s.handleUpdateProfile)
	s.Get("/me/device/new", s.handleNewDevice)
	s.Post("/me/device/new", s.handleAddDevice)
	s.Get("/", s.handleIndex)
	s.server.Handler = mux

	return s, nil
}

func (s *Server) Get(path string, handle httprouter.Handle) {
	s.router.GET(path, s.verifyRequest(handle))
}

func (s *Server) Post(path string, handle httprouter.Handle) {
	s.router.POST(path, s.verifyRequest(handle))
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

	http.Redirect(w, req, "/sa", http.StatusFound)
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

type agent struct {
	Name        string
	FromAddr    string
	ConnectedAt time.Time
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

func (s *Server) handleNewCert(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	s.RenderTemplate(w, "cert/new.tmpl", nil)
}

func (s *Server) handleNewClientCert(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	client := s.client.WithRequest(req)

	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if req.FormValue("csr") != "" {
		_, err := client.NewCertByCSR(req.FormValue("csr"), rpcclient.VerifyCommonName(req.FormValue("id")))
		if err != nil {
			logger.Log.Info("Failed sign CSR", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		switch req.FormValue("key_type") {
		case "ecdsa", "rsa":
		default:
			logger.Log.Info("Unknown key type", zap.String("key_type", req.FormValue("key_type")))
			w.WriteHeader(http.StatusForbidden)
			return
		}

		bit, err := strconv.ParseInt(req.FormValue("key_bits"), 10, 32)
		if err != nil {
			logger.Log.Info("Could not convert key_bit to integer")
			w.WriteHeader(http.StatusForbidden)
			return
		}

		err = client.NewCert(req.FormValue("id"), req.FormValue("key_type"), int(bit), req.FormValue("password"), req.FormValue("comment"))
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

func (s *Server) handleDownloadCACert(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=ca.crt")
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: s.Config.CertificateAuthority.Certificate.Raw}); err != nil {
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
	LastLogin      time.Time
}

type roleAndUser struct {
	Role  *rpc.RoleItem
	Users []user
}

func (s *Server) handleRoleIndex(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
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
	manageRoles := make([]*rpc.RoleItem, 0, len(roles))
	sortedUsers := make([]roleAndUser, 0)
	for _, v := range roles {
		if v.System {
			continue
		}
		manageRoles = append(manageRoles, v)

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

	s.RenderTemplate(w, "role/index.tmpl", struct {
		Roles []*rpc.RoleItem
		Users []roleAndUser
	}{
		Roles: manageRoles,
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

	allRoles, err := client.ListRole()
	if err != nil {
		logger.Log.Info("Failure fetch roles", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	roleMap := make(map[string][]string)
	for _, v := range allRoles {
		roleMap[v.Name] = v.Backends
	}
	allBackends, err := client.ListAllBackend()
	if err != nil {
		logger.Log.Info("Failure fetch backends", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	allBackendMap := make(map[string]*rpc.BackendItem)
	for _, v := range allBackends {
		allBackendMap[v.Name] = v
	}

	backendsMap := make(map[string]*rpc.BackendItem)
	for _, v := range u.Roles {
		backends, ok := roleMap[v]
		if !ok {
			continue
		}

		for _, b := range backends {
			backend, ok := allBackendMap[b]
			if !ok {
				continue
			}
			backendsMap[b] = backend
		}
	}
	backends := make([]*rpc.BackendItem, 0, len(backendsMap))
	for _, v := range backendsMap {
		backends = append(backends, v)
	}
	sort.Slice(backends, func(i, j int) bool {
		return backends[i].Name < backends[j].Name
	})

	s.RenderTemplate(w, "user/show.tmpl", struct {
		UserInfo *rpc.UserItem
		Backends []*rpc.BackendItem
	}{
		UserInfo: u,
		Backends: backends,
	})
}

func (s *Server) handleEditUserIndex(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
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

	s.RenderTemplate(w, "user/edit.tmpl", struct {
		Id       string
		UserInfo *rpc.UserItem
	}{
		Id:       u.Id,
		UserInfo: u,
	})
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

	http.Redirect(w, req, "/role", http.StatusFound)
}

func (s *Server) handleEditUser(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	client := s.client.WithRequest(req)

	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	u, err := client.GetUser(params.ByName("id"), false)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	u.LoginName = req.FormValue("login_name")

	if err := client.UpdateUser(u.Id, u); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/user/"+u.Id, http.StatusFound)
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

	http.Redirect(w, req, "/role", http.StatusFound)
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

	http.Redirect(w, req, "/role", http.StatusFound)
}

func (s *Server) handleMakeAdmin(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
	client := s.client.WithRequest(req)

	if err := client.ToggleAdmin(params.ByName("id")); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/role", http.StatusFound)
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

	agents, err := client.ListConnectedAgent()
	if err != nil {
		logger.Log.Info("Can't get connected agents", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	connectedAgents := make([]*agent, len(agents))
	for i, v := range agents {
		connectedAt, err := ptypes.Timestamp(v.ConnectedAt)
		if err != nil {
			logger.Log.Info("Can't convert to time.Time from protobuf.Timestamp. skipping", zap.String("name", v.Name))
			continue
		}
		connectedAgents[i] = &agent{
			Name:        v.Name,
			FromAddr:    v.FromAddr,
			ConnectedAt: connectedAt,
		}
	}

	s.RenderTemplate(w, "agent/index.tmpl", struct {
		ConnectedAgents     []*agent
		SignedCertificates  []*certificate
		RevokedCertificates []*certificate
	}{
		ConnectedAgents:     connectedAgents,
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
		for _, h := range v.HttpBackends {
			names = append(names, v.Name+h.Path)
		}
		if v.SocketBackend != nil {
			names = append(names, v.Name)
		}
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
		_, err := client.NewAgentCertByCSR(req.FormValue("csr"), req.FormValue("id"))
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

func (s *Server) handleMe(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	client := s.client.WithRequest(req)

	userId, ok := req.Context().Value(VerifiedUserIdKey).(string)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	signed, err := client.ListCert(rpcclient.CommonName(userId), rpcclient.IsDevice())
	if err != nil {
		logger.Log.Info("Failed get my certs")
	}

	signedCertificates := make([]*certificate, 0, len(signed))
	for _, v := range signed {
		serialNumber := big.NewInt(0)
		serialNumber.SetBytes(v.SerialNumber)
		issuedAt, err := ptypes.Timestamp(v.IssuedAt)
		if err != nil {
			continue
		}

		signedCertificates = append(signedCertificates, &certificate{
			SerialNumber: serialNumber.Text(16),
			IssuedAt:     issuedAt,
			CommonName:   v.CommonName,
			Comment:      v.Comment,
		})
	}

	s.RenderTemplate(w, "me/index.tmpl", struct {
		Devices []*certificate
	}{
		Devices: signedCertificates,
	})
}

func (s *Server) handleUpdateProfile(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/me", http.StatusFound)
}

func (s *Server) handleNewDevice(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	s.RenderTemplate(w, "me/new.tmpl", nil)
}

func (s *Server) handleAddDevice(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	client := s.client.WithRequest(req)

	if err := req.ParseForm(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if req.FormValue("csr") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	v := req.Context().Value(VerifiedUserIdKey)
	userId, ok := v.(string)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, err := client.NewCertByCSR(
		req.FormValue("csr"),
		rpcclient.OverrideCommonName(userId),
		rpcclient.IsDevice(),
		rpcclient.Comment(req.FormValue("name")),
	)
	if err != nil {
		logger.Log.Warn("Failed create certificate", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/me", http.StatusFound)
}

func (s *Server) RenderTemplate(w http.ResponseWriter, name string, data interface{}) {
	err := s.loader.Render(w, name, data)
	if err != nil {
		logger.Log.Info("Failed render template", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
	}
}

type verifiedUserIdKey struct{}

var VerifiedUserIdKey = verifiedUserIdKey{}

func (s *Server) verifyRequest(handle httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, params httprouter.Params) {
		if req.Header.Get(authproxy.TokenHeaderName) == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		claim := &authn.TokenClaims{}
		_, err := jwt.ParseWithClaims(req.Header.Get(authproxy.TokenHeaderName), claim, func(t *jwt.Token) (interface{}, error) {
			if t.Method != jwt.SigningMethodES256 {
				return nil, xerrors.New("dashboard: invalid signing method")
			}
			return s.publicKey, nil
		})
		if err != nil {
			logger.Log.Info("Failed parse JWT", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := claim.Valid(); err != nil {
			logger.Log.Warn("Invalid JWT token", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		req = req.WithContext(context.WithValue(req.Context(), VerifiedUserIdKey, claim.Id))

		handle(w, req, params)
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
