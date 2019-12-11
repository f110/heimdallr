package rpc

import (
	"context"

	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"go.uber.org/zap"
)

const (
	TokenMetadataKey = "token"
)

type ClusterService struct {
	clusterDatabase database.ClusterDatabase
}

var _ ClusterServer = &ClusterService{}

func NewClusterService(cluster database.ClusterDatabase) *ClusterService {
	return &ClusterService{clusterDatabase: cluster}
}

func (s *ClusterService) MemberList(ctx context.Context, req *RequestMemberList) (*ResponseMemberList, error) {
	members, err := s.clusterDatabase.MemberList(ctx)
	if err != nil {
		return nil, err
	}

	res := make([]*ClusterMember, len(members))
	for i, v := range members {
		res[i] = &ClusterMember{
			Id: v.Id,
		}
	}
	return &ResponseMemberList{Items: res}, nil
}

type AdminService struct {
	userDatabase database.UserDatabase
}

var _ AdminServer = &AdminService{}

func NewAdminService(user database.UserDatabase) *AdminService {
	return &AdminService{userDatabase: user}
}

func (s *AdminService) Ping(_ context.Context, _ *RequestPing) (*ResponsePong, error) {
	return &ResponsePong{}, nil
}

func (s *AdminService) UserList(_ context.Context, req *RequestUserList) (*ResponseUserList, error) {
	users, err := s.userDatabase.GetAll()
	if err != nil {
		return nil, err
	}
	res := make([]*UserItem, 0, len(users))
	for _, v := range users {
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
		res = append(res, &UserItem{
			Id:    v.Id,
			Roles: v.Roles,
		})
	}

	return &ResponseUserList{Items: res}, nil
}

func (s *AdminService) UserAdd(ctx context.Context, req *RequestUserAdd) (*ResponseUserAdd, error) {
	u, err := s.userDatabase.Get(req.Id)
	if err != nil && err != database.ErrUserNotFound {
		logger.Log.Info("Failure get user", zap.Error(err))
		return nil, err
	}

	if u != nil {
		u.Roles = append(u.Roles, req.Role)
	} else {
		u = &database.User{Id: req.Id, Roles: []string{req.Role}}
	}

	if err := s.userDatabase.Set(ctx, u); err != nil {
		logger.Log.Warn("Failure create or update user", zap.Error(err))
		return nil, err
	}

	return &ResponseUserAdd{Ok: true}, nil
}

func (s *AdminService) UserDel(ctx context.Context, req *RequestUserDel) (*ResponseUserDel, error) {
	u, err := s.userDatabase.Get(req.Id)
	if err != nil {
		logger.Log.Info("Failure get user", zap.Error(err))
		return nil, err
	}

	if req.Role == "" {
		if err := s.userDatabase.Delete(ctx, u.Id); err != nil {
			return nil, err
		}
		return &ResponseUserDel{Ok: true}, nil
	}

	for i := range u.Roles {
		if u.Roles[i] == req.Role {
			u.Roles = append(u.Roles[:i], u.Roles[i+1:]...)
			break
		}
	}

	if err := s.userDatabase.Set(ctx, u); err != nil {
		logger.Log.Warn("Failure delete role", zap.Error(err))
		return nil, err
	}
	return &ResponseUserDel{Ok: true}, nil
}
