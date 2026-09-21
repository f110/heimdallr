package rpctestutil

import (
	"context"
	"sync"

	"google.golang.org/grpc"

	"go.f110.dev/heimdallr/pkg/rpc"
)

type AdminClient struct {
	sync.Mutex

	PingCall             int
	UserListCall         int
	UserListCtx          context.Context
	UserListResponse     *rpc.ResponseUserList
	UserAddCall          int
	UserAddRequest       *rpc.RequestUserAdd
	UserDelCall          int
	UserDelRequest       *rpc.RequestUserDel
	UserGetCall          int
	UserGetResponse      *rpc.ResponseUserGet
	UserEditCall         int
	UserEditRequest      *rpc.RequestUserEdit
	BecomeMaintainerCall int
	ToggleAdminCall      int
	TokenNewCall         int
	TokenNewResponse     *rpc.ResponseTokenNew
	RoleListCall         int
	RoleListResponse     *rpc.ResponseRoleList
	BackendListCall      int
	BackendListRequest   *rpc.RequestBackendList
	BackendListResponse  *rpc.ResponseBackendList
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
	a.UserListCtx = ctx
	if a.UserListResponse != nil {
		return a.UserListResponse, nil
	}

	return &rpc.ResponseUserList{}, nil
}

func (a *AdminClient) UserAdd(ctx context.Context, in *rpc.RequestUserAdd, opts ...grpc.CallOption) (*rpc.ResponseUserAdd, error) {
	a.Lock()
	defer a.Unlock()
	a.UserAddCall++
	a.UserAddRequest = in

	return &rpc.ResponseUserAdd{}, nil
}

func (a *AdminClient) UserDel(ctx context.Context, in *rpc.RequestUserDel, opts ...grpc.CallOption) (*rpc.ResponseUserDel, error) {
	a.Lock()
	defer a.Unlock()
	a.UserDelCall++
	a.UserDelRequest = in

	return &rpc.ResponseUserDel{}, nil
}

func (a *AdminClient) UserGet(ctx context.Context, in *rpc.RequestUserGet, opts ...grpc.CallOption) (*rpc.ResponseUserGet, error) {
	a.Lock()
	defer a.Unlock()
	a.UserGetCall++
	if a.UserGetResponse != nil {
		return a.UserGetResponse, nil
	}

	return &rpc.ResponseUserGet{}, nil
}

func (a *AdminClient) UserEdit(ctx context.Context, in *rpc.RequestUserEdit, opts ...grpc.CallOption) (*rpc.ResponseUserEdit, error) {
	a.Lock()
	defer a.Unlock()
	a.UserEditCall++
	a.UserEditRequest = in

	return &rpc.ResponseUserEdit{}, nil
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
	if a.TokenNewResponse != nil {
		return a.TokenNewResponse, nil
	}

	return &rpc.ResponseTokenNew{}, nil
}

func (a *AdminClient) RoleList(ctx context.Context, in *rpc.RequestRoleList, opts ...grpc.CallOption) (*rpc.ResponseRoleList, error) {
	a.Lock()
	defer a.Unlock()
	a.RoleListCall++
	if a.RoleListResponse != nil {
		return a.RoleListResponse, nil
	}

	return &rpc.ResponseRoleList{}, nil
}

func (a *AdminClient) BackendList(ctx context.Context, in *rpc.RequestBackendList, opts ...grpc.CallOption) (*rpc.ResponseBackendList, error) {
	a.Lock()
	defer a.Unlock()
	a.BackendListCall++
	a.BackendListRequest = in
	if a.BackendListResponse != nil {
		return a.BackendListResponse, nil
	}

	return &rpc.ResponseBackendList{}, nil
}

type ClusterClient struct {
	sync.Mutex

	MemberListCall    int
	MemberStatCall    int
	AgentListCall     int
	AgentListResponse *rpc.ResponseAgentList
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
	if c.AgentListResponse != nil {
		return c.AgentListResponse, nil
	}

	return &rpc.ResponseAgentList{}, nil
}

type CertificateAuthorityClient struct {
	sync.Mutex

	GetSignedListCall      int
	GetSignedListResponse  *rpc.ResponseGetSignedList
	NewClientCertCall      int
	NewClientCertRequest   *rpc.RequestNewClientCert
	NewServerCertCall      int
	RevokeCall             int
	RevokeRequest          *rpc.CARequestRevoke
	GetCall                int
	GetRevokedListCall     int
	GetRevokedListResponse *rpc.ResponseGetRevokedList
	WatchRevokedListCall   int
}

func NewCertificateAuthorityClient() *CertificateAuthorityClient {
	return &CertificateAuthorityClient{}
}

func (c *CertificateAuthorityClient) GetSignedList(ctx context.Context, in *rpc.RequestGetSignedList, opts ...grpc.CallOption) (*rpc.ResponseGetSignedList, error) {
	c.Lock()
	defer c.Unlock()
	c.GetSignedListCall++
	if c.GetSignedListResponse != nil {
		return c.GetSignedListResponse, nil
	}

	return &rpc.ResponseGetSignedList{}, nil
}

func (c *CertificateAuthorityClient) NewClientCert(ctx context.Context, in *rpc.RequestNewClientCert, opts ...grpc.CallOption) (*rpc.ResponseNewClientCert, error) {
	c.Lock()
	defer c.Unlock()
	c.NewClientCertCall++
	c.NewClientCertRequest = in

	return &rpc.ResponseNewClientCert{Certificate: &rpc.CertItem{}}, nil
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
	c.RevokeRequest = in

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
	if c.GetRevokedListResponse != nil {
		return c.GetRevokedListResponse, nil
	}

	return &rpc.ResponseGetRevokedList{}, nil
}

func (c *CertificateAuthorityClient) WatchRevokedCert(ctx context.Context, in *rpc.RequestWatchRevokedCert, opts ...grpc.CallOption) (rpc.CertificateAuthority_WatchRevokedCertClient, error) {
	c.Lock()
	defer c.Unlock()
	c.WatchRevokedListCall++

	return nil, nil
}

type UserClient struct {
	sync.Mutex

	GetBackendsCall     int
	GetBackendsResponse *rpc.ResponseGetBackends
}

func NewUserClient() *UserClient {
	return &UserClient{}
}

func (u *UserClient) GetBackends(ctx context.Context, in *rpc.RequestGetBackends, opts ...grpc.CallOption) (*rpc.ResponseGetBackends, error) {
	u.Lock()
	defer u.Unlock()
	u.GetBackendsCall++
	if u.GetBackendsResponse != nil {
		return u.GetBackendsResponse, nil
	}

	return &rpc.ResponseGetBackends{}, nil
}
