package rpcservice

import (
	"context"

	"github.com/golang/protobuf/ptypes"
	"go.uber.org/zap"

	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc"
)

type ClusterService struct {
	clusterDatabase database.ClusterDatabase
	userDatabase    database.UserDatabase
	tokenDatabase   database.TokenDatabase
	relayDatabase   database.RelayLocator
}

var _ rpc.ClusterServer = &ClusterService{}

func NewClusterService(user database.UserDatabase, token database.TokenDatabase, cluster database.ClusterDatabase, relay database.RelayLocator) *ClusterService {
	return &ClusterService{
		userDatabase:    user,
		tokenDatabase:   token,
		clusterDatabase: cluster,
		relayDatabase:   relay,
	}
}

func (s *ClusterService) MemberList(ctx context.Context, _ *rpc.RequestMemberList) (*rpc.ResponseMemberList, error) {
	members, err := s.clusterDatabase.MemberList(ctx)
	if err != nil {
		return nil, err
	}

	res := make([]*rpc.ClusterMember, len(members))
	for i, v := range members {
		res[i] = &rpc.ClusterMember{
			Id: v.Id,
		}
	}
	return &rpc.ResponseMemberList{Items: res}, nil
}

func (s *ClusterService) MemberStat(ctx context.Context, _ *rpc.RequestMemberStat) (*rpc.ResponseMemberStat, error) {
	users, err := s.userDatabase.GetAll()
	if err != nil {
		return nil, err
	}
	tokens, err := s.tokenDatabase.AllTokens(ctx)
	if err != nil {
		return nil, err
	}

	return &rpc.ResponseMemberStat{
		Id:                 s.clusterDatabase.Id(),
		UserCount:          int32(len(users)),
		TokenCount:         int32(len(tokens)),
		ListenedRelayAddrs: s.relayDatabase.GetListenedAddrs(),
	}, nil
}

func (s *ClusterService) AgentList(_ context.Context, _ *rpc.RequestAgentList) (*rpc.ResponseAgentList, error) {
	connected := s.relayDatabase.ListAllConnectedAgents()

	result := make([]*rpc.Agent, len(connected))
	for i, v := range connected {
		connectedAt, err := ptypes.TimestampProto(v.ConnectedAt)
		if err != nil {
			return nil, err
		}

		result[i] = &rpc.Agent{
			Name:        v.Name,
			FromAddr:    v.FromAddr,
			ConnectedAt: connectedAt,
		}
	}

	return &rpc.ResponseAgentList{Items: result}, nil
}

func (s *ClusterService) DefragmentDatastore(ctx context.Context, _ *rpc.RequestDefragmentDatastore) (*rpc.ResponseDefragmentDatastore, error) {
	res := make(map[string]bool)
	for k, v := range s.clusterDatabase.Defragment(ctx) {
		if v == nil {
			res[k] = true
		} else {
			logger.Log.Info("Failed Defragment", zap.String("endpoint", k), zap.Error(v))
			res[k] = false
		}
	}

	return &rpc.ResponseDefragmentDatastore{Ok: res}, nil
}
