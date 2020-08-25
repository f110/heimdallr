package rpcservice

import (
	"context"

	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/rpc"
)

type UserService struct {
	userDatabase database.UserDatabase
}

var _ rpc.UserServer = &UserService{}

func NewUserService(user database.UserDatabase) *UserService {
	return &UserService{userDatabase: user}
}

func (s *UserService) GetSSHKey(ctx context.Context, req *rpc.RequestGetSSHKey) (*rpc.ResponseGetSSHKey, error) {
	user := req.GetUserId()
	if user == "" {
		u, err := extractUser(ctx)
		if err != nil {
			return nil, err
		}
		user = u.Id
	}

	keys, err := s.userDatabase.GetSSHKeys(ctx, user)
	if err != nil {
		return nil, xerrors.New("rpcservice: ssh keys not found")
	}

	return &rpc.ResponseGetSSHKey{
		UserId: keys.UserId,
		Key:    keys.Keys,
	}, nil
}

func (s *UserService) SetSSHKey(ctx context.Context, req *rpc.RequestSetSSHKey) (*rpc.ResponseSetSSHKey, error) {
	user, err := extractUser(ctx)
	if err != nil {
		return nil, err
	}

	if err := s.userDatabase.SetSSHKeys(ctx, &database.SSHKeys{UserId: user.Id, Keys: req.Key}); err != nil {
		return nil, err
	}

	return &rpc.ResponseSetSSHKey{Ok: true}, nil
}
