package rpctestutil

import (
	"context"

	"google.golang.org/grpc"

	"github.com/f110/lagrangian-proxy/pkg/rpc"
)

type AdminClient struct{}

func NewAdminClient() *AdminClient {
	return &AdminClient{}
}

func (a *AdminClient) Ping(ctx context.Context, in *rpc.RequestPing, opts ...grpc.CallOption) (*rpc.ResponsePong, error) {
	panic("implement me")
}

func (a *AdminClient) UserList(ctx context.Context, in *rpc.RequestUserList, opts ...grpc.CallOption) (*rpc.ResponseUserList, error) {
	panic("implement me")
}

func (a *AdminClient) UserAdd(ctx context.Context, in *rpc.RequestUserAdd, opts ...grpc.CallOption) (*rpc.ResponseUserAdd, error) {
	panic("implement me")
}

func (a *AdminClient) UserDel(ctx context.Context, in *rpc.RequestUserDel, opts ...grpc.CallOption) (*rpc.ResponseUserDel, error) {
	panic("implement me")
}

func (a *AdminClient) UserGet(ctx context.Context, in *rpc.RequestUserGet, opts ...grpc.CallOption) (*rpc.ResponseUserGet, error) {
	panic("implement me")
}

func (a *AdminClient) BecomeMaintainer(ctx context.Context, in *rpc.RequestBecomeMaintainer, opts ...grpc.CallOption) (*rpc.ResponseBecomeMaintainer, error) {
	panic("implement me")
}

func (a *AdminClient) ToggleAdmin(ctx context.Context, in *rpc.RequestToggleAdmin, opts ...grpc.CallOption) (*rpc.ResponseToggleAdmin, error) {
	panic("implement me")
}

func (a *AdminClient) TokenNew(ctx context.Context, in *rpc.RequestTokenNew, opts ...grpc.CallOption) (*rpc.ResponseTokenNew, error) {
	panic("implement me")
}

func (a *AdminClient) RoleList(ctx context.Context, in *rpc.RequestRoleList, opts ...grpc.CallOption) (*rpc.ResponseRoleList, error) {
	panic("implement me")
}

func (a *AdminClient) BackendList(ctx context.Context, in *rpc.RequestBackendList, opts ...grpc.CallOption) (*rpc.ResponseBackendList, error) {
	panic("implement me")
}

type ClusterClient struct {
}

func NewClusterClient() *ClusterClient {
	return &ClusterClient{}
}

func (c *ClusterClient) MemberList(ctx context.Context, in *rpc.RequestMemberList, opts ...grpc.CallOption) (*rpc.ResponseMemberList, error) {
	panic("implement me")
}

func (c *ClusterClient) MemberStat(ctx context.Context, in *rpc.RequestMemberStat, opts ...grpc.CallOption) (*rpc.ResponseMemberStat, error) {
	panic("implement me")
}

func (c *ClusterClient) AgentList(ctx context.Context, in *rpc.RequestAgentList, opts ...grpc.CallOption) (*rpc.ResponseAgentList, error) {
	panic("implement me")
}

func (c *ClusterClient) DefragmentDatastore(ctx context.Context, in *rpc.RequestDefragmentDatastore, opts ...grpc.CallOption) (*rpc.ResponseDefragmentDatastore, error) {
	panic("implement me")
}

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

type CertificateAuthorityClient struct {
}

func NewCertificateAuthorityClient() *CertificateAuthorityClient {
	return &CertificateAuthorityClient{}
}

func (c *CertificateAuthorityClient) GetSignedList(ctx context.Context, in *rpc.RequestGetSignedList, opts ...grpc.CallOption) (*rpc.ResponseGetSignedList, error) {
	panic("implement me")
}

func (c *CertificateAuthorityClient) NewClientCert(ctx context.Context, in *rpc.RequestNewClientCert, opts ...grpc.CallOption) (*rpc.ResponseNewClientCert, error) {
	panic("implement me")
}

func (c *CertificateAuthorityClient) NewServerCert(ctx context.Context, in *rpc.RequestNewServerCert, opts ...grpc.CallOption) (*rpc.ResponseNewServerCert, error) {
	panic("implement me")
}

func (c *CertificateAuthorityClient) Revoke(ctx context.Context, in *rpc.CARequestRevoke, opts ...grpc.CallOption) (*rpc.CAResponseRevoke, error) {
	panic("implement me")
}

func (c *CertificateAuthorityClient) Get(ctx context.Context, in *rpc.CARequestGet, opts ...grpc.CallOption) (*rpc.CAResponseGet, error) {
	panic("implement me")
}

func (c *CertificateAuthorityClient) GetRevokedList(ctx context.Context, in *rpc.RequestGetRevokedList, opts ...grpc.CallOption) (*rpc.ResponseGetRevokedList, error) {
	panic("implement me")
}

func (c *CertificateAuthorityClient) WatchRevokedCert(ctx context.Context, in *rpc.RequestWatchRevokedCert, opts ...grpc.CallOption) (rpc.CertificateAuthority_WatchRevokedCertClient, error) {
	panic("implement me")
}
