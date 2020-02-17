package rpctestutil

import (
	"context"

	"google.golang.org/grpc"

	"github.com/f110/lagrangian-proxy/pkg/rpc"
)

type AuthorityClient struct {
}

func NewAuthorityClient() *AuthorityClient {
	return &AuthorityClient{}
}

func (a *AuthorityClient) SignRequest(_ context.Context, in *rpc.RequestSignRequest, opts ...grpc.CallOption) (*rpc.ResponseSignResponse, error) {
	return &rpc.ResponseSignResponse{}, nil
}

func (a *AuthorityClient) GetPublicKey(ctx context.Context, in *rpc.RequestGetPublicKey, opts ...grpc.CallOption) (*rpc.ResponseGetPublicKey, error) {
	panic("implement me")
}
