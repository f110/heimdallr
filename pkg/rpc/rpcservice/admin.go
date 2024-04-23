package rpcservice

import (
	"context"

	"go.f110.dev/xerrors"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"

	"go.f110.dev/heimdallr/pkg/auth"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/rpc"
)

type AdminService struct {
	Config       *configv2.Config
	userDatabase database.UserDatabase
}

var _ rpc.AdminServer = &AdminService{}

func NewAdminService(conf *configv2.Config, user database.UserDatabase) *AdminService {
	return &AdminService{
		Config:       conf,
		userDatabase: user,
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
		if req.GetRole() != "" {
			ok := false
			for _, r := range v.Roles {
				if r == req.GetRole() {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		if req.GetServiceAccount() {
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
	u, err := s.userDatabase.Get(req.GetId())
	if err != nil {
		return &rpc.ResponseUserGet{}, err
	}

	res := rpc.DatabaseUserToRPCUser(u)
	if req.GetWithTokens() {
		t, err := s.userDatabase.GetAccessTokens(req.GetId())
		if err != nil {
			return nil, err
		}
		tokens := make([]*rpc.AccessTokenItem, len(t))
		for i, v := range t {
			issuedAt := timestamppb.New(v.CreatedAt)
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
	u, err := s.userDatabase.Get(req.GetId(), database.WithoutCache)
	if err != nil && err != database.ErrUserNotFound {
		logger.Log.Info("Failure get user", zap.Error(err))
		return nil, err
	}

	t := database.UserTypeNormal
	switch req.GetType() {
	case rpc.UserType_SERVICE_ACCOUNT:
		t = database.UserTypeServiceAccount
	}
	if u != nil {
		u.Roles = append(u.Roles, req.GetRole())
	} else {
		u = &database.User{Id: req.GetId(), Roles: []string{req.GetRole()}, Type: t, Comment: req.GetComment()}
	}

	if err := s.userDatabase.Set(ctx, u); err != nil {
		logger.Log.Warn("Failure create or update user", zap.Error(err))
		return nil, err
	}

	logger.Audit.Info("Add user", zap.Any("user", u), auditBy(ctx))
	return &rpc.ResponseUserAdd{Ok: true}, nil
}

func (s *AdminService) UserEdit(ctx context.Context, req *rpc.RequestUserEdit) (*rpc.ResponseUserEdit, error) {
	u, err := s.userDatabase.Get(req.GetId(), database.WithoutCache)
	if err != nil {
		logger.Log.Info("Failed get user", zap.Error(err), zap.String("id", req.GetId()))
		return nil, err
	}

	u.LoginName = req.User.LoginName

	if err := s.userDatabase.Set(ctx, u); err != nil {
		logger.Log.Warn("Failed update user", zap.Error(err), zap.String("id", u.Id))
		return nil, err
	}

	logger.Audit.Info("Edit user", zap.Any("user", u), auditBy(ctx))
	return &rpc.ResponseUserEdit{Ok: true}, nil
}

func (s *AdminService) UserDel(ctx context.Context, req *rpc.RequestUserDel) (*rpc.ResponseUserDel, error) {
	u, err := s.userDatabase.Get(req.GetId())
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
		if u.Roles[i] == req.GetRole() {
			u.Roles = append(u.Roles[:i], u.Roles[i+1:]...)
			break
		}
	}
	if _, ok := u.MaintainRoles[req.GetRole()]; ok {
		delete(u.MaintainRoles, req.GetRole())
	}

	if err := s.userDatabase.Set(ctx, u); err != nil {
		logger.Log.Warn("Failure delete role", zap.Error(err))
		return nil, err
	}

	logger.Audit.Info("Delete user", zap.String("user", u.Id), zap.String("role", req.GetRole()), auditBy(ctx))
	return &rpc.ResponseUserDel{Ok: true}, nil
}

func (s *AdminService) BecomeMaintainer(ctx context.Context, req *rpc.RequestBecomeMaintainer) (*rpc.ResponseBecomeMaintainer, error) {
	u, err := s.userDatabase.Get(req.GetId())
	if err != nil {
		logger.Log.Info("Failure get user", zap.Error(err))
		return nil, err
	}

	if _, err := s.Config.AuthorizationEngine.GetRole(req.GetRole()); err != nil {
		logger.Log.Info("Role not found", zap.String("role", req.Role))
		return nil, err
	}

	ok := false
	for _, v := range u.Roles {
		if v == req.GetRole() {
			ok = true
		}
	}
	if !ok {
		return nil, xerrors.New("rpc: user doesn't belong role")
	}

	u.MaintainRoles[req.GetRole()] = true
	if err := s.userDatabase.Set(ctx, u); err != nil {
		logger.Log.Warn("Failure update user", zap.Error(err))
		return nil, err
	}

	logger.Audit.Info("Become maintainer", zap.String("user", u.Id), zap.String("role", req.GetRole()), auditBy(ctx))
	return &rpc.ResponseBecomeMaintainer{Ok: true}, nil
}

func (s *AdminService) ToggleAdmin(ctx context.Context, req *rpc.RequestToggleAdmin) (*rpc.ResponseToggleAdmin, error) {
	u, err := s.userDatabase.Get(req.GetId())
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
	if user, err := extractUser(ctx); err != nil {
		return nil, err
	} else {
		issuer = user.Id
	}

	if _, err := s.userDatabase.Get(issuer); err != nil {
		return nil, err
	}
	if _, err := s.userDatabase.Get(req.GetUserId()); err != nil {
		return nil, err
	}

	newToken, err := auth.NewAccessToken(req.GetName(), req.GetUserId(), issuer)
	if err != nil {
		return nil, err
	}

	if err := s.userDatabase.SetAccessToken(ctx, newToken); err != nil {
		logger.Log.Info("Failed set access token", zap.Error(err))
		return nil, err
	}

	issuedAt := timestamppb.New(newToken.CreatedAt)
	logger.Audit.Info("Issue token", zap.String("user", req.GetUserId()), auditBy(ctx))
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

	roles := s.Config.AuthorizationEngine.GetAllRoles()

	res := make([]*rpc.RoleItem, 0, len(roles))
	for _, v := range roles {
		if !user.Admin {
			if _, ok := user.MaintainRoles[v.Name]; !ok {
				continue
			}
		}
		r, err := s.Config.AuthorizationEngine.GetRole(v.Name)
		if err != nil {
			continue
		}
		backends, err := s.Config.AccessProxy.GetBackendsByRole(r)
		if err != nil {
			continue
		}
		backendNames := make([]string, len(backends))
		for i := range backends {
			backendNames[i] = backends[i].Name
		}

		res = append(res, &rpc.RoleItem{
			Name:        v.Name,
			Title:       v.Title,
			Description: v.Description,
			System:      v.System,
			Backends:    backendNames,
		})
	}

	return &rpc.ResponseRoleList{Items: res}, nil
}

func (s *AdminService) BackendList(_ context.Context, req *rpc.RequestBackendList) (*rpc.ResponseBackendList, error) {
	backends := s.Config.AccessProxy.GetAllBackends()

	res := make([]*rpc.BackendItem, 0, len(backends))
	for _, v := range backends {
		if req.GetAgent() && !v.Agent() {
			continue
		}

		var httpBackends []*rpc.HTTPBackend
		if v.HTTP != nil {
			for _, h := range v.HTTP {
				httpBackends = append(httpBackends, &rpc.HTTPBackend{Path: h.Path, Agent: h.Agent})
			}
		}
		var socketBackend *rpc.SocketBackend
		if v.Socket != nil {
			socketBackend = &rpc.SocketBackend{Agent: v.Socket.Agent}
		}

		res = append(res, &rpc.BackendItem{
			Name:          v.Name,
			Description:   v.Description,
			Fqdn:          v.FQDN,
			HttpBackends:  httpBackends,
			SocketBackend: socketBackend,
			Host:          v.Host,
		})
	}

	return &rpc.ResponseBackendList{Items: res}, nil
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
