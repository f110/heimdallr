package rpcclient

import (
	"context"
	"math/big"
	"net"
	"net/http"
	"sync"

	"go.f110.dev/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"go.f110.dev/heimdallr/pkg/auth/token"
	"go.f110.dev/heimdallr/pkg/config/userconfig"
	"go.f110.dev/heimdallr/pkg/rpc"
)

const (
	TokenHeaderName = "X-Auth-Token"
)

var loggerOnce sync.Once

type RequestOpt func(any)

type ClientWithUserToken struct {
	*Client
}

func (u *ClientWithUserToken) WithRequest(req *http.Request) *ClientWithUserToken {
	if req.Header.Get(TokenHeaderName) == "" {
		return u
	}

	return u.WithToken(req.Header.Get(TokenHeaderName))
}

func (u *ClientWithUserToken) WithToken(token string) *ClientWithUserToken {
	c := *u.Client
	c.md = []string{rpc.JwtTokenMetadataKey, token}

	return &ClientWithUserToken{Client: &c}
}

func NewClientWithUserToken(conn *grpc.ClientConn) *ClientWithUserToken {
	c := &ClientWithUserToken{}
	c.Client = &Client{}
	c.Client.setConn(conn)

	return c
}

type Client struct {
	conn          *grpc.ClientConn
	adminClient   rpc.AdminClient
	clusterClient rpc.ClusterClient
	caClient      rpc.CertificateAuthorityClient
	userClient    rpc.UserClient
	md            []string
	ka            keepalive.ClientParameters
}

func NewWithStaticToken(ctx context.Context, conn *grpc.ClientConn) (*Client, error) {
	adminClient := rpc.NewAdminClient(conn)

	uc, err := userconfig.New()
	if err != nil {
		return nil, err
	}

	t, err := uc.GetToken()
	if err != nil {
		return nil, err
	}
	var accessToken string
	if !t.IsExpired() {
		accessToken = t.Token
	}
	md := []string{rpc.TokenMetadataKey, accessToken}
	_, err = adminClient.Ping(metadata.AppendToOutgoingContext(ctx, md...), &rpc.RequestPing{}, grpc.WaitForReady(true))
	if err != nil {
		endpoint, err := extractEndpointFromError(err)
		if err != nil {
			return nil, err
		}
		tokenClient := token.NewClient(net.DefaultResolver)
		newToken, _, err := tokenClient.RequestToken(endpoint, "", false)
		if err != nil {
			return nil, err
		}
		md = []string{rpc.TokenMetadataKey, newToken}
	}

	c := &Client{md: md}
	c.setConn(conn)

	return c, nil
}

func NewWithInternalToken(conn *grpc.ClientConn, token string) (*Client, error) {
	c := &Client{md: []string{rpc.InternalTokenMetadataKey, token}}
	c.setConn(conn)

	return c, nil
}

func NewWithClient(a rpc.AdminClient, c rpc.ClusterClient, ca rpc.CertificateAuthorityClient, user rpc.UserClient) *Client {
	return &Client{
		adminClient:   a,
		clusterClient: c,
		caClient:      ca,
		userClient:    user,
	}
}

func (c *Client) setConn(conn *grpc.ClientConn) {
	c.conn = conn
	c.adminClient = rpc.NewAdminClient(conn)
	c.clusterClient = rpc.NewClusterClient(conn)
	c.caClient = rpc.NewCertificateAuthorityClient(conn)
	c.userClient = rpc.NewUserClient(conn)
}

// callContext attaches the credential of the client to ctx. The deadline and the cancellation of
// ctx are kept so that they reach the rpc server.
func (c *Client) callContext(ctx context.Context) context.Context {
	if len(c.md) == 0 {
		return ctx
	}

	return metadata.AppendToOutgoingContext(ctx, c.md...)
}

func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) Alive() bool {
	switch c.conn.GetState() {
	case connectivity.Idle, connectivity.Ready:
		return true
	default:
		return false
	}
}

func (c *Client) AddUser(ctx context.Context, id, role string) error {
	_, err := c.adminClient.UserAdd(c.callContext(ctx), &rpc.RequestUserAdd{Id: id, Role: role, Type: rpc.UserType_NORMAL})
	return xerrors.WithStack(err)
}

func (c *Client) DeleteUser(ctx context.Context, id string, role string) error {
	_, err := c.adminClient.UserDel(c.callContext(ctx), &rpc.RequestUserDel{Id: id, Role: role})
	return xerrors.WithStack(err)
}

func (c *Client) ListAllUser(ctx context.Context) ([]*rpc.UserItem, error) {
	return c.ListUser(ctx, "")
}

func (c *Client) ListUser(ctx context.Context, role string) ([]*rpc.UserItem, error) {
	res, err := c.adminClient.UserList(c.callContext(ctx), &rpc.RequestUserList{Role: role})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return res.Items, nil
}

func (c *Client) ListServiceAccount(ctx context.Context) ([]*rpc.UserItem, error) {
	res, err := c.adminClient.UserList(c.callContext(ctx), &rpc.RequestUserList{ServiceAccount: true})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return res.Items, nil
}

func (c *Client) NewServiceAccount(ctx context.Context, id, comment string) error {
	_, err := c.adminClient.UserAdd(c.callContext(ctx), &rpc.RequestUserAdd{Id: id, Type: rpc.UserType_SERVICE_ACCOUNT, Comment: comment})
	return xerrors.WithStack(err)
}

func (c *Client) GetUser(ctx context.Context, id string, withToken bool) (*rpc.UserItem, error) {
	res, err := c.adminClient.UserGet(c.callContext(ctx), &rpc.RequestUserGet{Id: id, WithTokens: withToken})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return res.User, nil
}

func (c *Client) UpdateUser(ctx context.Context, id string, user *rpc.UserItem) error {
	_, err := c.adminClient.UserEdit(c.callContext(ctx), &rpc.RequestUserEdit{Id: id, User: user})
	return xerrors.WithStack(err)
}

func (c *Client) UserBecomeMaintainer(ctx context.Context, id, role string) error {
	_, err := c.adminClient.BecomeMaintainer(c.callContext(ctx), &rpc.RequestBecomeMaintainer{Id: id, Role: role})
	if err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func (c *Client) ToggleAdmin(ctx context.Context, id string) error {
	_, err := c.adminClient.ToggleAdmin(c.callContext(ctx), &rpc.RequestToggleAdmin{Id: id})
	if err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func (c *Client) NewToken(ctx context.Context, name, userId string) (*rpc.AccessTokenItem, error) {
	res, err := c.adminClient.TokenNew(c.callContext(ctx), &rpc.RequestTokenNew{Name: name, UserId: userId})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return res.Item, nil
}

func (c *Client) ClusterMemberList(ctx context.Context) ([]*rpc.ClusterMember, error) {
	res, err := c.clusterClient.MemberList(c.callContext(ctx), &rpc.RequestMemberList{})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return res.Items, nil
}

func (c *Client) ListConnectedAgent(ctx context.Context) ([]*rpc.Agent, error) {
	res, err := c.clusterClient.AgentList(c.callContext(ctx), &rpc.RequestAgentList{})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return res.Items, nil
}

func (c *Client) ListRole(ctx context.Context) ([]*rpc.RoleItem, error) {
	res, err := c.adminClient.RoleList(c.callContext(ctx), &rpc.RequestRoleList{})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return res.Items, nil
}

func (c *Client) ListAllBackend(ctx context.Context) ([]*rpc.BackendItem, error) {
	res, err := c.adminClient.BackendList(c.callContext(ctx), &rpc.RequestBackendList{})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return res.Items, nil
}

func (c *Client) ListAgentBackend(ctx context.Context) ([]*rpc.BackendItem, error) {
	res, err := c.adminClient.BackendList(c.callContext(ctx), &rpc.RequestBackendList{Agent: true})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return res.Items, nil
}

func (c *Client) ListCert(ctx context.Context, opts ...RequestOpt) ([]*rpc.CertItem, error) {
	req := &rpc.RequestGetSignedList{}
	for _, v := range opts {
		v(req)
	}

	res, err := c.caClient.GetSignedList(c.callContext(ctx), req)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return res.Items, nil
}

func (c *Client) ListRevokedCert(ctx context.Context) ([]*rpc.CertItem, error) {
	res, err := c.caClient.GetRevokedList(c.callContext(ctx), &rpc.RequestGetRevokedList{})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return res.Items, nil
}

func (c *Client) NewCert(ctx context.Context, commonName, keyType string, keyBits int, password, comment string) error {
	_, err := c.caClient.NewClientCert(c.callContext(ctx), &rpc.RequestNewClientCert{CommonName: commonName, KeyType: keyType, KeyBits: int32(keyBits), Password: password, Comment: comment})
	if err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func (c *Client) NewCertByCSR(ctx context.Context, csr string, opts ...RequestOpt) (*rpc.CertItem, error) {
	req := &rpc.RequestNewClientCert{Csr: csr}
	for _, v := range opts {
		v(req)
	}

	res, err := c.caClient.NewClientCert(c.callContext(ctx), req)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return res.Certificate, nil
}

func (c *Client) NewAgentCert(ctx context.Context, commonName, comment string) error {
	_, err := c.caClient.NewClientCert(c.callContext(ctx), &rpc.RequestNewClientCert{Agent: true, CommonName: commonName, Comment: comment})
	if err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func (c *Client) NewAgentCertByCSR(ctx context.Context, csr string, commonName string) ([]byte, error) {
	res, err := c.caClient.NewClientCert(c.callContext(ctx), &rpc.RequestNewClientCert{Agent: true, Csr: csr, CommonName: commonName})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	if res.Certificate != nil {
		return res.Certificate.Certificate, nil
	}

	return nil, nil
}

func (c *Client) NewServerCert(ctx context.Context, csr []byte) ([]byte, error) {
	res, err := c.caClient.NewServerCert(c.callContext(ctx), &rpc.RequestNewServerCert{SigningRequest: csr})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return res.Certificate, nil
}

func (c *Client) RevokeCert(ctx context.Context, serialNumber *big.Int) error {
	_, err := c.caClient.Revoke(c.callContext(ctx), &rpc.CARequestRevoke{SerialNumber: serialNumber.Bytes()})
	if err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func (c *Client) GetCert(ctx context.Context, serialNumber *big.Int) (*rpc.CertItem, error) {
	res, err := c.caClient.Get(c.callContext(ctx), &rpc.CARequestGet{SerialNumber: serialNumber.Bytes()})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return res.Item, nil
}

func (c *Client) GetBackends(ctx context.Context) ([]*rpc.BackendItem, error) {
	res, err := c.userClient.GetBackends(c.callContext(ctx), &rpc.RequestGetBackends{})
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return res.Items, nil
}

func extractEndpointFromError(err error) (string, error) {
	e, ok := status.FromError(err)
	if !ok {
		return "", err
	}
	if len(e.Details()) == 0 {
		return "", err
	}

	if v, ok := e.Details()[0].(*rpc.ErrorUnauthorized); ok {
		return v.Endpoint, nil
	}

	return "", err
}

func OverrideCommonName(cn string) RequestOpt {
	return func(req any) {
		v, ok := req.(interface {
			SetOverrideCommonName(string)
		})
		if !ok {
			return
		}

		v.SetOverrideCommonName(cn)
	}
}

func VerifyCommonName(cn string) RequestOpt {
	return func(req any) {
		v, ok := req.(interface {
			SetCommonName(string)
		})
		if !ok {
			return
		}

		v.SetCommonName(cn)
	}
}

func IsDevice() RequestOpt {
	return func(req any) {
		v, ok := req.(interface {
			SetDevice(bool)
		})
		if !ok {
			return
		}

		v.SetDevice(true)
	}
}

func CommonName(cn string) RequestOpt {
	return VerifyCommonName(cn)
}

func Comment(c string) RequestOpt {
	return func(req any) {
		v, ok := req.(interface {
			SetComment(string)
		})
		if !ok {
			return
		}

		v.SetComment(c)
	}
}
