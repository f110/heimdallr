package rpc

import (
	"context"

	"github.com/f110/lagrangian-proxy/pkg/database"
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

type UserService struct {
	userDatabase database.UserDatabase
}

var _ UserServer = &UserService{}

func NewUserService(user database.UserDatabase) *UserService {
	return &UserService{userDatabase: user}
}

func (s *UserService) List(_ context.Context, _ *RequestUserList) (*ResponseUserList, error) {
	users, err := s.userDatabase.GetAll()
	if err != nil {
		return nil, err
	}
	res := make([]*UserItem, len(users))
	for i, v := range users {
		res[i] = &UserItem{
			Id:    v.Id,
			Roles: v.Roles,
		}
	}

	return &ResponseUserList{Items: res}, nil
}
