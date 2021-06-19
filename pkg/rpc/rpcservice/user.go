package rpcservice

import (
	"context"
	"sort"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/rpc"
)

type UserService struct {
	Config *configv2.Config
}

var _ rpc.UserServer = &UserService{}

func NewUserService(conf *configv2.Config) *UserService {
	return &UserService{Config: conf}
}

func (u *UserService) GetBackends(ctx context.Context, _ *rpc.RequestGetBackends) (*rpc.ResponseGetBackends, error) {
	user, err := extractUser(ctx)
	if err != nil {
		return nil, err
	}

	accessibleBackends := make(map[string]*configv2.Backend)
	for _, v := range user.Roles {
		role, err := u.Config.AuthorizationEngine.GetRole(v)
		if err != nil {
			continue
		}
		b, err := u.Config.AccessProxy.GetBackendsByRole(role)
		if err != nil {
			continue
		}
		for _, v := range b {
			accessibleBackends[v.Name] = v
		}
	}

	res := make([]*rpc.BackendItem, 0, len(accessibleBackends))
	for _, v := range accessibleBackends {
		// Do not return information about backend.
		// Because the user doesn't need to know about backend.
		res = append(res, &rpc.BackendItem{
			Name:        v.Name,
			Description: v.Description,
			Fqdn:        v.FQDN,
			Host:        v.Host,
		})
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].Name < res[j].Name
	})

	return &rpc.ResponseGetBackends{Items: res}, nil
}
