package dashboard

import (
	"context"
	"sort"
	"strings"

	"connectrpc.com/connect"
	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/rpc"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
)

type AdminService struct {
	service
}

var _ AdminServiceHandler = &AdminService{}

func NewAdminService(c *rpcclient.ClientWithUserToken) *AdminService {
	return &AdminService{rpcClient: c}
}

func (s *AdminService) ListUsers(ctx context.Context, _ *connect.Request[ListUsersRequest]) (*connect.Response[ListUsersResponse], error) {
	users, err := s.client(ctx).ListAllUser(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	sort.Slice(users, func(i, j int) bool {
		if users[i].Admin == users[j].Admin {
			return strings.Compare(users[i].Id, users[j].Id) < 0
		}
		return users[i].Admin
	})

	res := make([]*User, 0, len(users))
	for _, v := range users {
		res = append(res, newUser(v))
	}

	return connect.NewResponse(&ListUsersResponse{Users: res}), nil
}

// GetUser returns the user and the backends that the user can reach through the roles.
func (s *AdminService) GetUser(ctx context.Context, req *connect.Request[GetUserRequest]) (*connect.Response[GetUserResponse], error) {
	if req.Msg.Id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, xerrors.New("dashboard: id is empty"))
	}
	client := s.client(ctx)

	u, err := client.GetUser(ctx, req.Msg.Id, false)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	allRoles, err := client.ListRole(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	roleMap := make(map[string][]string)
	for _, v := range allRoles {
		roleMap[v.Name] = v.Backends
	}

	allBackends, err := client.ListAllBackend(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	allBackendMap := make(map[string]*rpc.BackendItem)
	for _, v := range allBackends {
		allBackendMap[v.Name] = v
	}

	backendsMap := make(map[string]*rpc.BackendItem)
	for _, v := range u.Roles {
		for _, b := range roleMap[v] {
			if backend, ok := allBackendMap[b]; ok {
				backendsMap[b] = backend
			}
		}
	}
	backends := make([]*Backend, 0, len(backendsMap))
	for _, v := range backendsMap {
		backends = append(backends, newBackend(v))
	}
	sort.Slice(backends, func(i, j int) bool {
		return backends[i].Name < backends[j].Name
	})

	return connect.NewResponse(&GetUserResponse{User: newUser(u), Backends: backends}), nil
}

func (s *AdminService) AddUser(ctx context.Context, req *connect.Request[AddUserRequest]) (*connect.Response[AddUserResponse], error) {
	if req.Msg.Id == "" || req.Msg.Role == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, xerrors.New("dashboard: id and role are required"))
	}

	if err := s.client(ctx).AddUser(ctx, req.Msg.Id, req.Msg.Role); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&AddUserResponse{}), nil
}

func (s *AdminService) UpdateUser(ctx context.Context, req *connect.Request[UpdateUserRequest]) (*connect.Response[UpdateUserResponse], error) {
	if req.Msg.Id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, xerrors.New("dashboard: id is empty"))
	}
	client := s.client(ctx)

	u, err := client.GetUser(ctx, req.Msg.Id, false)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	u.LoginName = req.Msg.LoginName

	if err := client.UpdateUser(ctx, u.Id, u); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&UpdateUserResponse{}), nil
}

func (s *AdminService) DeleteUser(ctx context.Context, req *connect.Request[DeleteUserRequest]) (*connect.Response[DeleteUserResponse], error) {
	if req.Msg.Id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, xerrors.New("dashboard: id is empty"))
	}

	if err := s.client(ctx).DeleteUser(ctx, req.Msg.Id, req.Msg.Role); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&DeleteUserResponse{}), nil
}

func (s *AdminService) BecomeMaintainer(ctx context.Context, req *connect.Request[BecomeMaintainerRequest]) (*connect.Response[BecomeMaintainerResponse], error) {
	if req.Msg.Id == "" || req.Msg.Role == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, xerrors.New("dashboard: id and role are required"))
	}

	if err := s.client(ctx).UserBecomeMaintainer(ctx, req.Msg.Id, req.Msg.Role); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&BecomeMaintainerResponse{}), nil
}

func (s *AdminService) ToggleAdmin(ctx context.Context, req *connect.Request[ToggleAdminRequest]) (*connect.Response[ToggleAdminResponse], error) {
	if req.Msg.Id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, xerrors.New("dashboard: id is empty"))
	}

	if err := s.client(ctx).ToggleAdmin(ctx, req.Msg.Id); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&ToggleAdminResponse{}), nil
}

// ListRoles returns the manageable roles with the members of each role.
func (s *AdminService) ListRoles(ctx context.Context, _ *connect.Request[ListRolesRequest]) (*connect.Response[ListRolesResponse], error) {
	client := s.client(ctx)

	users, err := client.ListUser(ctx, "")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	userMap := make(map[string][]*rpc.UserItem)
	for _, v := range users {
		for _, r := range v.Roles {
			userMap[r] = append(userMap[r], v)
		}
	}

	roles, err := client.ListRole(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	res := make([]*RoleMembers, 0, len(roles))
	for _, role := range roles {
		if role.System {
			continue
		}

		members := make([]*RoleMember, 0, len(userMap[role.Name]))
		for _, u := range userMap[role.Name] {
			maintainer := false
			for _, r := range u.MaintainRoles {
				if r == role.Name {
					maintainer = true
				}
			}
			members = append(members, &RoleMember{
				Id:         u.Id,
				Type:       newUserType(u.Type),
				Maintainer: maintainer,
				Admin:      u.Admin,
			})
		}
		sort.Slice(members, func(i, j int) bool {
			return strings.Compare(members[i].Id, members[j].Id) < 0
		})

		res = append(res, &RoleMembers{
			Role:    &Role{Name: role.Name, Title: role.Title, Description: role.Description},
			Members: members,
		})
	}

	return connect.NewResponse(&ListRolesResponse{Roles: res}), nil
}

func (s *AdminService) ListServiceAccounts(ctx context.Context, _ *connect.Request[ListServiceAccountsRequest]) (*connect.Response[ListServiceAccountsResponse], error) {
	accounts, err := s.client(ctx).ListServiceAccount(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	sort.Slice(accounts, func(i, j int) bool {
		return strings.Compare(accounts[i].Id, accounts[j].Id) < 0
	})

	res := make([]*User, 0, len(accounts))
	for _, v := range accounts {
		res = append(res, newUser(v))
	}

	return connect.NewResponse(&ListServiceAccountsResponse{Accounts: res}), nil
}

func (s *AdminService) CreateServiceAccount(ctx context.Context, req *connect.Request[CreateServiceAccountRequest]) (*connect.Response[CreateServiceAccountResponse], error) {
	if req.Msg.Id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, xerrors.New("dashboard: id is empty"))
	}

	if err := s.client(ctx).NewServiceAccount(ctx, req.Msg.Id, req.Msg.Comment); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&CreateServiceAccountResponse{}), nil
}

func (s *AdminService) ListServiceAccountTokens(ctx context.Context, req *connect.Request[ListServiceAccountTokensRequest]) (*connect.Response[ListServiceAccountTokensResponse], error) {
	if req.Msg.Id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, xerrors.New("dashboard: id is empty"))
	}

	u, err := s.client(ctx).GetUser(ctx, req.Msg.Id, true)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	tokens := make([]*AccessToken, 0, len(u.Tokens))
	for _, v := range u.Tokens {
		tokens = append(tokens, newAccessToken(v))
	}
	sort.Slice(tokens, func(i, j int) bool {
		return timestampSeconds(tokens[i].IssuedAt) > timestampSeconds(tokens[j].IssuedAt)
	})

	return connect.NewResponse(&ListServiceAccountTokensResponse{Tokens: tokens}), nil
}

// CreateServiceAccountToken returns the value of the new token. The value can not be read again.
func (s *AdminService) CreateServiceAccountToken(ctx context.Context, req *connect.Request[CreateServiceAccountTokenRequest]) (*connect.Response[CreateServiceAccountTokenResponse], error) {
	if req.Msg.Id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, xerrors.New("dashboard: id is empty"))
	}

	newToken, err := s.client(ctx).NewToken(ctx, req.Msg.Name, req.Msg.Id)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&CreateServiceAccountTokenResponse{Name: newToken.Name, Value: newToken.Value}), nil
}
