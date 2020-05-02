package rpctestutil

import (
	"context"
	"sync"

	"google.golang.org/grpc"

	"github.com/f110/lagrangian-proxy/pkg/rpc"
)

type AuthorityClient struct {
	sync.Mutex

	SignRequestCall  int
	GetPublicKeyCall int
}

func NewAuthorityClient() *AuthorityClient {
	return &AuthorityClient{}
}

func (a *AuthorityClient) SignRequest(_ context.Context, in *rpc.RequestSignRequest, opts ...grpc.CallOption) (*rpc.ResponseSignResponse, error) {
	a.Lock()
	defer a.Unlock()
	a.SignRequestCall++

	return &rpc.ResponseSignResponse{}, nil
}

func (a *AuthorityClient) GetPublicKey(ctx context.Context, in *rpc.RequestGetPublicKey, opts ...grpc.CallOption) (*rpc.ResponseGetPublicKey, error) {
	a.Lock()
	defer a.Unlock()
	a.GetPublicKeyCall++

	return &rpc.ResponseGetPublicKey{}, nil
}

type AdminClient struct {
	sync.Mutex

	PingCall             int
	UserListCall         int
	UserAddCall          int
	UserDelCall          int
	UserGetCall          int
	BecomeMaintainerCall int
	ToggleAdminCall      int
	TokenNewCall         int
	RoleListCall         int
	BackendListCall      int
}

func NewAdminClient() *AdminClient {
	return &AdminClient{}
}

func (a *AdminClient) Ping(ctx context.Context, in *rpc.RequestPing, opts ...grpc.CallOption) (*rpc.ResponsePong, error) {
	a.Lock()
	defer a.Unlock()
	a.PingCall++

	return &rpc.ResponsePong{}, nil
}

func (a *AdminClient) UserList(ctx context.Context, in *rpc.RequestUserList, opts ...grpc.CallOption) (*rpc.ResponseUserList, error) {
	a.Lock()
	defer a.Unlock()
	a.UserListCall++

	return &rpc.ResponseUserList{}, nil
}

func (a *AdminClient) UserAdd(ctx context.Context, in *rpc.RequestUserAdd, opts ...grpc.CallOption) (*rpc.ResponseUserAdd, error) {
	a.Lock()
	defer a.Unlock()
	a.UserAddCall++

	return &rpc.ResponseUserAdd{}, nil
}

func (a *AdminClient) UserDel(ctx context.Context, in *rpc.RequestUserDel, opts ...grpc.CallOption) (*rpc.ResponseUserDel, error) {
	a.Lock()
	defer a.Unlock()
	a.UserDelCall++

	return &rpc.ResponseUserDel{}, nil
}

func (a *AdminClient) UserGet(ctx context.Context, in *rpc.RequestUserGet, opts ...grpc.CallOption) (*rpc.ResponseUserGet, error) {
	a.Lock()
	defer a.Unlock()
	a.UserGetCall++

	return &rpc.ResponseUserGet{}, nil
}

func (a *AdminClient) BecomeMaintainer(ctx context.Context, in *rpc.RequestBecomeMaintainer, opts ...grpc.CallOption) (*rpc.ResponseBecomeMaintainer, error) {
	a.Lock()
	defer a.Unlock()
	a.BecomeMaintainerCall++

	return &rpc.ResponseBecomeMaintainer{}, nil
}

func (a *AdminClient) ToggleAdmin(ctx context.Context, in *rpc.RequestToggleAdmin, opts ...grpc.CallOption) (*rpc.ResponseToggleAdmin, error) {
	a.Lock()
	defer a.Unlock()
	a.ToggleAdminCall++

	return &rpc.ResponseToggleAdmin{}, nil
}

func (a *AdminClient) TokenNew(ctx context.Context, in *rpc.RequestTokenNew, opts ...grpc.CallOption) (*rpc.ResponseTokenNew, error) {
	a.Lock()
	defer a.Unlock()
	a.TokenNewCall++

	return &rpc.ResponseTokenNew{}, nil
}

func (a *AdminClient) RoleList(ctx context.Context, in *rpc.RequestRoleList, opts ...grpc.CallOption) (*rpc.ResponseRoleList, error) {
	a.Lock()
	defer a.Unlock()
	a.RoleListCall++

	return &rpc.ResponseRoleList{}, nil
}

func (a *AdminClient) BackendList(ctx context.Context, in *rpc.RequestBackendList, opts ...grpc.CallOption) (*rpc.ResponseBackendList, error) {
	a.Lock()
	defer a.Unlock()
	a.BackendListCall++

	return &rpc.ResponseBackendList{}, nil
}

type ClusterClient struct {
	sync.Mutex

	MemberListCall int
	MemberStatCall int
	AgentListCall  int
}

func NewClusterClient() *ClusterClient {
	return &ClusterClient{}
}

func (c *ClusterClient) MemberList(ctx context.Context, in *rpc.RequestMemberList, opts ...grpc.CallOption) (*rpc.ResponseMemberList, error) {
	c.Lock()
	defer c.Unlock()
	c.MemberListCall++

	return &rpc.ResponseMemberList{}, nil
}

func (c *ClusterClient) MemberStat(ctx context.Context, in *rpc.RequestMemberStat, opts ...grpc.CallOption) (*rpc.ResponseMemberStat, error) {
	c.Lock()
	defer c.Unlock()
	c.MemberStatCall++

	return &rpc.ResponseMemberStat{}, nil
}

func (c *ClusterClient) AgentList(ctx context.Context, in *rpc.RequestAgentList, opts ...grpc.CallOption) (*rpc.ResponseAgentList, error) {
	c.Lock()
	defer c.Unlock()
	c.AgentListCall++

	return &rpc.ResponseAgentList{}, nil
}

type CertificateAuthorityClient struct {
	sync.Mutex

	GetSignedListCall    int
	NewClientCertCall    int
	NewServerCertCall    int
	RevokeCall           int
	GetCall              int
	GetRevokedListCall   int
	WatchRevokedListCall int
}

func NewCertificateAuthorityClient() *CertificateAuthorityClient {
	return &CertificateAuthorityClient{}
}

func (c *CertificateAuthorityClient) GetSignedList(ctx context.Context, in *rpc.RequestGetSignedList, opts ...grpc.CallOption) (*rpc.ResponseGetSignedList, error) {
	c.Lock()
	defer c.Unlock()
	c.GetSignedListCall++

	return &rpc.ResponseGetSignedList{}, nil
}

func (c *CertificateAuthorityClient) NewClientCert(ctx context.Context, in *rpc.RequestNewClientCert, opts ...grpc.CallOption) (*rpc.ResponseNewClientCert, error) {
	c.Lock()
	defer c.Unlock()
	c.NewClientCertCall++

	return &rpc.ResponseNewClientCert{}, nil
}

func (c *CertificateAuthorityClient) NewServerCert(ctx context.Context, in *rpc.RequestNewServerCert, opts ...grpc.CallOption) (*rpc.ResponseNewServerCert, error) {
	c.Lock()
	defer c.Unlock()
	c.NewServerCertCall++

	return &rpc.ResponseNewServerCert{}, nil
}

func (c *CertificateAuthorityClient) Revoke(ctx context.Context, in *rpc.CARequestRevoke, opts ...grpc.CallOption) (*rpc.CAResponseRevoke, error) {
	c.Lock()
	defer c.Unlock()
	c.RevokeCall++

	return &rpc.CAResponseRevoke{}, nil
}

func (c *CertificateAuthorityClient) Get(ctx context.Context, in *rpc.CARequestGet, opts ...grpc.CallOption) (*rpc.CAResponseGet, error) {
	c.Lock()
	defer c.Unlock()
	c.GetCall++

	return &rpc.CAResponseGet{}, nil
}

func (c *CertificateAuthorityClient) GetRevokedList(ctx context.Context, in *rpc.RequestGetRevokedList, opts ...grpc.CallOption) (*rpc.ResponseGetRevokedList, error) {
	c.Lock()
	defer c.Unlock()
	c.GetRevokedListCall++

	return &rpc.ResponseGetRevokedList{}, nil
}

func (c *CertificateAuthorityClient) WatchRevokedCert(ctx context.Context, in *rpc.RequestWatchRevokedCert, opts ...grpc.CallOption) (rpc.CertificateAuthority_WatchRevokedCertClient, error) {
	c.Lock()
	defer c.Unlock()
	c.WatchRevokedListCall++

	return nil, nil
}
