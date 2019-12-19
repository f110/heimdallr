package rpcservice

import (
	"context"
	"math/big"

	"github.com/f110/lagrangian-proxy/pkg/auth"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc"
	"github.com/golang/protobuf/ptypes"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

type AdminService struct {
	Config       *config.Config
	userDatabase database.UserDatabase
	ca           database.CertificateAuthority
}

var _ rpc.AdminServer = &AdminService{}

func NewAdminService(conf *config.Config, user database.UserDatabase, ca database.CertificateAuthority) *AdminService {
	return &AdminService{
		Config:       conf,
		userDatabase: user,
		ca:           ca,
	}
}

func (s *AdminService) Ping(_ context.Context, _ *rpc.RequestPing) (*rpc.ResponsePong, error) {
	return &rpc.ResponsePong{}, nil
}

func (s *AdminService) UserList(ctx context.Context, req *rpc.RequestUserList) (*rpc.ResponseUserList, error) {
	user, err := extractUser(ctx)
	if err != nil {
		return nil, err
	}

	users, err := s.userDatabase.GetAll()
	if err != nil {
		return nil, err
	}
	res := make([]*rpc.UserItem, 0, len(users))
	for _, v := range users {
		// filtered by request parameter
		if req.Role != "" {
			ok := false
			for _, r := range v.Roles {
				if r == req.Role {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		if req.ServiceAccount {
			if !v.ServiceAccount() {
				continue
			}
		}

		// filtered by privilege of requester
		if !user.Admin {
			permit := false
			for _, r := range v.Roles {
				if _, ok := user.MaintainRoles[r]; ok {
					permit = true
					break
				}
			}
			if !permit {
				continue
			}
		}

		res = append(res, rpc.DatabaseUserToRPCUser(v))
	}

	return &rpc.ResponseUserList{Items: res}, nil
}

func (s *AdminService) UserGet(_ context.Context, req *rpc.RequestUserGet) (*rpc.ResponseUserGet, error) {
	u, err := s.userDatabase.Get(req.Id)
	if err != nil {
		return &rpc.ResponseUserGet{}, err
	}

	res := rpc.DatabaseUserToRPCUser(u)
	if req.WithTokens {
		t, err := s.userDatabase.GetAccessTokens(req.Id)
		if err != nil {
			return nil, err
		}
		tokens := make([]*rpc.AccessTokenItem, len(t))
		for i, v := range t {
			issuedAt, err := ptypes.TimestampProto(v.CreatedAt)
			if err != nil {
				return nil, err
			}
			tokens[i] = &rpc.AccessTokenItem{
				Name:     v.Name,
				Value:    v.Value,
				Issuer:   v.Issuer,
				IssuedAt: issuedAt,
			}
		}
		res.Tokens = tokens
	}

	return &rpc.ResponseUserGet{User: res, Ok: true}, nil
}

func (s *AdminService) UserAdd(ctx context.Context, req *rpc.RequestUserAdd) (*rpc.ResponseUserAdd, error) {
	u, err := s.userDatabase.Get(req.Id)
	if err != nil && err != database.ErrUserNotFound {
		logger.Log.Info("Failure get user", zap.Error(err))
		return nil, err
	}

	t := database.UserTypeNormal
	switch req.Type {
	case rpc.UserType_SERVICE_ACCOUNT:
		t = database.UserTypeServiceAccount
	}
	if u != nil {
		u.Roles = append(u.Roles, req.Role)
	} else {
		u = &database.User{Id: req.Id, Roles: []string{req.Role}, Type: t, Comment: req.Comment}
	}

	if err := s.userDatabase.Set(ctx, u); err != nil {
		logger.Log.Warn("Failure create or update user", zap.Error(err))
		return nil, err
	}

	logger.Audit.Info("Add user", zap.Any("user", u), auditBy(ctx))
	return &rpc.ResponseUserAdd{Ok: true}, nil
}

func (s *AdminService) UserDel(ctx context.Context, req *rpc.RequestUserDel) (*rpc.ResponseUserDel, error) {
	u, err := s.userDatabase.Get(req.Id)
	if err != nil {
		logger.Log.Info("Failure get user", zap.Error(err))
		return nil, err
	}

	if req.Role == "" {
		if err := s.userDatabase.Delete(ctx, u.Id); err != nil {
			return nil, err
		}

		logger.Audit.Info("Delete user", zap.String("user", u.Id), zap.String("by", u.Id))
		return &rpc.ResponseUserDel{Ok: true}, nil
	}

	for i := range u.Roles {
		if u.Roles[i] == req.Role {
			u.Roles = append(u.Roles[:i], u.Roles[i+1:]...)
			break
		}
	}
	if _, ok := u.MaintainRoles[req.Role]; ok {
		delete(u.MaintainRoles, req.Role)
	}

	if err := s.userDatabase.Set(ctx, u); err != nil {
		logger.Log.Warn("Failure delete role", zap.Error(err))
		return nil, err
	}

	logger.Audit.Info("Delete user", zap.String("user", u.Id), zap.String("role", req.Role), auditBy(ctx))
	return &rpc.ResponseUserDel{Ok: true}, nil
}

func (s *AdminService) BecomeMaintainer(ctx context.Context, req *rpc.RequestBecomeMaintainer) (*rpc.ResponseBecomeMaintainer, error) {
	u, err := s.userDatabase.Get(req.Id)
	if err != nil {
		logger.Log.Info("Failure get user", zap.Error(err))
		return nil, err
	}

	if _, err := s.Config.General.GetRole(req.Role); err != nil {
		logger.Log.Info("Role not found", zap.String("role", req.Role))
		return nil, err
	}

	ok := false
	for _, v := range u.Roles {
		if v == req.Role {
			ok = true
		}
	}
	if !ok {
		return nil, xerrors.New("rpc: user doesn't belong role")
	}

	u.MaintainRoles[req.Role] = true
	if err := s.userDatabase.Set(ctx, u); err != nil {
		logger.Log.Warn("Failure update user", zap.Error(err))
		return nil, err
	}

	logger.Audit.Info("Become maintainer", zap.String("user", u.Id), zap.String("role", req.Role), auditBy(ctx))
	return &rpc.ResponseBecomeMaintainer{Ok: true}, nil
}

func (s *AdminService) ToggleAdmin(ctx context.Context, req *rpc.RequestToggleAdmin) (*rpc.ResponseToggleAdmin, error) {
	u, err := s.userDatabase.Get(req.Id)
	if err != nil {
		logger.Log.Info("Failure get user", zap.Error(err))
		return nil, err
	}

	u.Admin = !u.Admin
	if err := s.userDatabase.Set(ctx, u); err != nil {
		logger.Log.Warn("Failure update user", zap.Error(err))
		return nil, err
	}

	logger.Audit.Info("Change admin privilege", zap.String("user", u.Id), zap.Bool("to", u.Admin), auditBy(ctx))
	return &rpc.ResponseToggleAdmin{Ok: true}, nil
}

func (s *AdminService) TokenNew(ctx context.Context, req *rpc.RequestTokenNew) (*rpc.ResponseTokenNew, error) {
	issuer := ""
	user := ctx.Value("user")
	if user != nil {
		if v, ok := user.(*database.User); ok {
			issuer = v.Id
		} else {
			return nil, xerrors.New("rpcservice: unauthorized")
		}
	} else {
		return nil, xerrors.New("rpcservice: unauthorized")
	}
	_, err := s.userDatabase.Get(issuer)
	if err != nil {
		return nil, err
	}
	_, err = s.userDatabase.Get(req.UserId)
	if err != nil {
		return nil, err
	}

	newToken, err := auth.NewAccessToken(req.Name, req.UserId, issuer)
	if err != nil {
		return nil, err
	}

	if err := s.userDatabase.SetAccessToken(ctx, newToken); err != nil {
		logger.Log.Info("Failed set access token", zap.Error(err))
		return nil, err
	}

	issuedAt, err := ptypes.TimestampProto(newToken.CreatedAt)
	if err != nil {
		return nil, err
	}

	logger.Audit.Info("Issue token", zap.String("user", req.UserId), auditBy(ctx))
	return &rpc.ResponseTokenNew{Item: &rpc.AccessTokenItem{
		Name:     newToken.Name,
		Value:    newToken.Value,
		Issuer:   newToken.Issuer,
		IssuedAt: issuedAt,
	}}, nil
}

func (s *AdminService) RoleList(ctx context.Context, _ *rpc.RequestRoleList) (*rpc.ResponseRoleList, error) {
	user, err := extractUser(ctx)
	if err != nil {
		return nil, err
	}

	roles := s.Config.General.GetAllRoles()

	res := make([]*rpc.RoleItem, 0, len(roles))
	for _, v := range roles {
		if !user.Admin {
			if _, ok := user.MaintainRoles[v.Name]; !ok {
				continue
			}
		}

		res = append(res, &rpc.RoleItem{
			Name:        v.Name,
			Title:       v.Title,
			Description: v.Description,
		})
	}

	return &rpc.ResponseRoleList{Items: res}, nil
}

func (s *AdminService) BackendList(_ context.Context, req *rpc.RequestBackendList) (*rpc.ResponseBackendList, error) {
	backends := s.Config.General.GetAllBackends()

	res := make([]*rpc.BackendItem, 0, len(backends))
	for _, v := range backends {
		if req.Agent && !v.Agent {
			continue
		}

		res = append(res, &rpc.BackendItem{Name: v.Name})
	}

	return &rpc.ResponseBackendList{Items: res}, nil
}

func (s *AdminService) CertList(ctx context.Context, _ *rpc.RequestCertList) (*rpc.ResponseCertList, error) {
	certs, err := s.ca.GetSignedCertificates(ctx)
	if err != nil {
		return nil, err
	}

	res := make([]*rpc.CertItem, len(certs))
	for i, c := range certs {
		res[i] = rpc.DatabaseCertToRPCCert(c)
	}

	return &rpc.ResponseCertList{Items: res}, nil
}

func (s *AdminService) RevokedCertList(_ context.Context, _ *rpc.RequestRevokedCertList) (*rpc.ResponseRevokedCertList, error) {
	certs := s.ca.GetRevokedCertificates()

	res := make([]*rpc.CertItem, len(certs))
	for i, c := range certs {
		res[i] = rpc.DatabaseRevokedCertToRPCCert(c)
	}

	return &rpc.ResponseRevokedCertList{Items: res}, nil
}

func (s *AdminService) CertNew(ctx context.Context, req *rpc.RequestCertNew) (*rpc.ResponseCertNew, error) {
	var err error
	if req.Agent {
		if _, ok := s.Config.General.GetBackend(req.CommonName); !ok {
			return nil, xerrors.New("rpc: unknown backend")
		}

		_, err = s.ca.NewAgentCertificate(ctx, req.CommonName, req.Comment)
	} else {
		_, err = s.ca.NewClientCertificate(ctx, req.CommonName, req.Password, req.Comment)
	}
	if err != nil {
		return nil, err
	}

	logger.Audit.Info("Generate certificate", zap.String("common_name", req.CommonName), auditBy(ctx))
	return &rpc.ResponseCertNew{Ok: true}, nil
}

func (s *AdminService) CertRevoke(ctx context.Context, req *rpc.RequestCertRevoke) (*rpc.ResponseCertRevoke, error) {
	serialNumber := big.NewInt(0)
	serialNumber.SetBytes(req.SerialNumber)

	signed, err := s.ca.GetSignedCertificate(ctx, serialNumber)
	if err != nil {
		return nil, err
	}

	err = s.ca.Revoke(ctx, signed)
	if err != nil {
		return nil, err
	}

	logger.Audit.Info("Revoke certificate", zap.String("common_name", signed.Certificate.Subject.CommonName), auditBy(ctx))
	return &rpc.ResponseCertRevoke{Ok: true}, nil
}

func (s *AdminService) CertGet(ctx context.Context, req *rpc.RequestCertGet) (*rpc.ResponseCertGet, error) {
	serialNumber := big.NewInt(0)
	serialNumber.SetBytes(req.SerialNumber)

	cert, err := s.ca.GetSignedCertificate(ctx, serialNumber)
	if err != nil {
		return nil, err
	}

	return &rpc.ResponseCertGet{Item: rpc.DatabaseCertToRPCCertWithByte(cert)}, nil
}

func extractUser(ctx context.Context) (*database.User, error) {
	u := ctx.Value("user")
	if u != nil {
		if v, ok := u.(*database.User); ok {
			return v, nil
		} else {
			return nil, xerrors.New("rpcservice: unauthorized")
		}
	} else {
		return nil, xerrors.New("rpcservice: unauthorized")
	}
}

func auditBy(ctx context.Context) zap.Field {
	user, err := extractUser(ctx)
	if err != nil {
		return zap.Skip()
	}

	return zap.String("by", user.Id)
}
