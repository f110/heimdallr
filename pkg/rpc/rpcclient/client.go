package rpcclient

import (
	"context"
	"math/big"
	"net/http"
	"sync"

	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"go.f110.dev/heimdallr/pkg/auth/token"
	"go.f110.dev/heimdallr/pkg/config/userconfig"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/rpc"
)

const (
	TokenHeaderName = "X-Auth-Token"
)

var loggerOnce sync.Once

type RequestOpt func(interface{})

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
	ctx := metadata.AppendToOutgoingContext(context.Background(), rpc.JwtTokenMetadataKey, token)
	c := &Client{md: ctx}
	c.setConn(u.Client.conn)

	return &ClientWithUserToken{Client: c}
}

func NewClientWithUserToken(conn *grpc.ClientConn) *ClientWithUserToken {
	c := &ClientWithUserToken{}
	c.Client = &Client{md: context.Background()}
	c.Client.setConn(conn)

	return c
}

type Client struct {
	conn          *grpc.ClientConn
	adminClient   rpc.AdminClient
	clusterClient rpc.ClusterClient
	caClient      rpc.CertificateAuthorityClient
	userClient    rpc.UserClient
	md            context.Context
	ka            keepalive.ClientParameters
}

func NewWithStaticToken(conn *grpc.ClientConn) (*Client, error) {
	adminClient := rpc.NewAdminClient(conn)

	uc, err := userconfig.New()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	t, err := uc.GetToken()
	if err != nil {
		return nil, xerrors.Errorf(": %v", nil)
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), rpc.TokenMetadataKey, t)
	_, err = adminClient.Ping(ctx, &rpc.RequestPing{}, grpc.WaitForReady(true))
	if err != nil {
		endpoint, err := extractEndpointFromError(err)
		if err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}
		tokenClient := token.NewClient()
		newToken, err := tokenClient.RequestToken(endpoint)
		ctx = metadata.AppendToOutgoingContext(context.Background(), rpc.TokenMetadataKey, newToken)
	}

	c := &Client{md: ctx}
	c.setConn(conn)

	return c, nil
}

func NewWithInternalToken(conn *grpc.ClientConn, token string) (*Client, error) {
	ctx := metadata.AppendToOutgoingContext(context.Background(), rpc.InternalTokenMetadataKey, token)

	c := &Client{md: ctx}
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

func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) Alive() bool {
	switch c.conn.GetState() {
	case connectivity.Ready:
		return true
	default:
		return false
	}
}

func (c *Client) AddUser(id, role string) error {
	_, err := c.adminClient.UserAdd(c.md, &rpc.RequestUserAdd{Id: id, Role: role, Type: rpc.UserType_NORMAL})
	return err
}

func (c *Client) DeleteUser(id string, role string) error {
	_, err := c.adminClient.UserDel(c.md, &rpc.RequestUserDel{Id: id, Role: role})
	return err
}

func (c *Client) ListAllUser() ([]*rpc.UserItem, error) {
	return c.ListUser("")
}

func (c *Client) ListUser(role string) ([]*rpc.UserItem, error) {
	res, err := c.adminClient.UserList(c.md, &rpc.RequestUserList{Role: role})
	if err != nil {
		return nil, err
	}

	return res.Items, nil
}

func (c *Client) ListServiceAccount() ([]*rpc.UserItem, error) {
	res, err := c.adminClient.UserList(c.md, &rpc.RequestUserList{ServiceAccount: true})
	if err != nil {
		return nil, err
	}

	return res.Items, nil
}

func (c *Client) NewServiceAccount(id, comment string) error {
	_, err := c.adminClient.UserAdd(c.md, &rpc.RequestUserAdd{Id: id, Type: rpc.UserType_SERVICE_ACCOUNT, Comment: comment})
	return err
}

func (c *Client) GetUser(id string, withToken bool) (*rpc.UserItem, error) {
	res, err := c.adminClient.UserGet(c.md, &rpc.RequestUserGet{Id: id, WithTokens: withToken})
	if err != nil {
		return nil, err
	}

	return res.User, nil
}

func (c *Client) UpdateUser(id string, user *rpc.UserItem) error {
	_, err := c.adminClient.UserEdit(c.md, &rpc.RequestUserEdit{Id: id, User: user})
	return err
}

func (c *Client) UserBecomeMaintainer(id, role string) error {
	_, err := c.adminClient.BecomeMaintainer(c.md, &rpc.RequestBecomeMaintainer{Id: id, Role: role})
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) ToggleAdmin(id string) error {
	_, err := c.adminClient.ToggleAdmin(c.md, &rpc.RequestToggleAdmin{Id: id})
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) NewToken(name, userId string) (*rpc.AccessTokenItem, error) {
	res, err := c.adminClient.TokenNew(c.md, &rpc.RequestTokenNew{Name: name, UserId: userId})
	if err != nil {
		return nil, err
	}

	return res.Item, nil
}

func (c *Client) ClusterMemberList() ([]*rpc.ClusterMember, error) {
	res, err := c.clusterClient.MemberList(c.md, &rpc.RequestMemberList{})
	if err != nil {
		return nil, err
	}

	return res.Items, nil
}

func (c *Client) ListConnectedAgent() ([]*rpc.Agent, error) {
	res, err := c.clusterClient.AgentList(c.md, &rpc.RequestAgentList{})
	if err != nil {
		return nil, err
	}

	return res.Items, nil
}

func (c *Client) ListRole() ([]*rpc.RoleItem, error) {
	res, err := c.adminClient.RoleList(c.md, &rpc.RequestRoleList{})
	if err != nil {
		return nil, err
	}

	return res.Items, nil
}

func (c *Client) ListAllBackend() ([]*rpc.BackendItem, error) {
	res, err := c.adminClient.BackendList(c.md, &rpc.RequestBackendList{})
	if err != nil {
		return nil, err
	}

	return res.Items, nil
}

func (c *Client) ListAgentBackend() ([]*rpc.BackendItem, error) {
	res, err := c.adminClient.BackendList(c.md, &rpc.RequestBackendList{Agent: true})
	if err != nil {
		return nil, err
	}

	return res.Items, nil
}

func (c *Client) ListCert(opts ...RequestOpt) ([]*rpc.CertItem, error) {
	req := &rpc.RequestGetSignedList{}
	for _, v := range opts {
		v(req)
	}

	res, err := c.caClient.GetSignedList(c.md, req)
	if err != nil {
		return nil, err
	}

	return res.Items, nil
}

func (c *Client) ListRevokedCert() ([]*rpc.CertItem, error) {
	res, err := c.caClient.GetRevokedList(c.md, &rpc.RequestGetRevokedList{})
	if err != nil {
		return nil, err
	}

	return res.Items, nil
}

func (c *Client) NewCert(commonName, keyType string, keyBits int, password, comment string) error {
	_, err := c.caClient.NewClientCert(c.md, &rpc.RequestNewClientCert{CommonName: commonName, KeyType: keyType, KeyBits: int32(keyBits), Password: password, Comment: comment})
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) NewCertByCSR(csr string, opts ...RequestOpt) (*rpc.CertItem, error) {
	req := &rpc.RequestNewClientCert{Csr: csr}
	for _, v := range opts {
		v(req)
	}

	res, err := c.caClient.NewClientCert(c.md, req)
	if err != nil {
		return nil, err
	}

	return res.Certificate, nil
}

func (c *Client) NewAgentCert(commonName, comment string) error {
	_, err := c.caClient.NewClientCert(c.md, &rpc.RequestNewClientCert{Agent: true, CommonName: commonName, Comment: comment})
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) NewAgentCertByCSR(csr string, commonName string) ([]byte, error) {
	res, err := c.caClient.NewClientCert(c.md, &rpc.RequestNewClientCert{Agent: true, Csr: csr, CommonName: commonName})
	if err != nil {
		return nil, err
	}
	if res.Certificate != nil {
		return res.Certificate.Certificate, nil
	}

	return nil, nil
}

func (c *Client) NewServerCert(csr []byte) ([]byte, error) {
	res, err := c.caClient.NewServerCert(c.md, &rpc.RequestNewServerCert{SigningRequest: csr})
	if err != nil {
		return nil, err
	}

	return res.Certificate, nil
}

func (c *Client) RevokeCert(serialNumber *big.Int) error {
	_, err := c.caClient.Revoke(c.md, &rpc.CARequestRevoke{SerialNumber: serialNumber.Bytes()})
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) GetCert(serialNumber *big.Int) (*rpc.CertItem, error) {
	res, err := c.caClient.Get(c.md, &rpc.CARequestGet{SerialNumber: serialNumber.Bytes()})
	if err != nil {
		return nil, err
	}

	return res.Item, nil
}

func (c *Client) GetSSHKey(userId string) (string, error) {
	keys, err := c.userClient.GetSSHKey(c.md, &rpc.RequestGetSSHKey{UserId: userId})
	if err != nil {
		return "", err
	}

	return keys.Key, nil
}

func (c *Client) SetSSHKey(key string) error {
	res, err := c.userClient.SetSSHKey(c.md, &rpc.RequestSetSSHKey{Key: key})
	if err != nil {
		return err
	}

	if !res.Ok {
		return xerrors.New("rpcclient: Failed update ssh key")
	}

	return nil
}

func (c *Client) GetGPGKey(userId string) (string, error) {
	key, err := c.userClient.GetGPGKey(c.md, &rpc.RequestGetGPGKey{UserId: userId})
	if err != nil {
		return "", err
	}

	return key.Key, nil
}

func (c *Client) SetGPGKey(key string) error {
	res, err := c.userClient.SetGPGKey(c.md, &rpc.RequestSetGPGKey{Key: key})
	if err != nil {
		return err
	}

	if !res.Ok {
		return xerrors.New("rpcclient: Failed update gpg key")
	}

	return nil
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
	return func(req interface{}) {
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
	return func(req interface{}) {
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
	return func(req interface{}) {
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
	return func(req interface{}) {
		v, ok := req.(interface {
			SetComment(string)
		})
		if !ok {
			return
		}

		v.SetComment(c)
	}
}

func OverrideGrpcLogger() {
	loggerOnce.Do(func() {
		grpc_zap.ReplaceGrpcLoggerV2(logger.Log)
	})
}
