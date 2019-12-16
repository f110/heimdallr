package rpcclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/http"
	"sync"

	"github.com/f110/lagrangian-proxy/pkg/auth/token"
	"github.com/f110/lagrangian-proxy/pkg/frontproxy"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var loggerOnce sync.Once

type ClientWithUserToken struct {
	*Client
}

func (u *ClientWithUserToken) WithRequest(req *http.Request) *ClientWithUserToken {
	if req.Header.Get(frontproxy.TokenHeaderName) == "" {
		return u
	}

	ctx := metadata.AppendToOutgoingContext(context.Background(), rpc.JwtTokenMetadataKey, req.Header.Get(frontproxy.TokenHeaderName))
	c := &Client{
		conn:          u.Client.conn,
		adminClient:   u.Client.adminClient,
		clusterClient: u.Client.clusterClient,
		md:            ctx,
	}

	return &ClientWithUserToken{Client: c}
}

func NewClientWithUserToken(pool *x509.CertPool, host, serverName string) (*ClientWithUserToken, error) {
	overrideGrpcLogger()

	c := &ClientWithUserToken{}
	cred := credentials.NewTLS(&tls.Config{ServerName: serverName, RootCAs: pool})
	conn, err := grpc.Dial(host, grpc.WithTransportCredentials(cred))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	c.Client = &Client{
		conn:          conn,
		adminClient:   rpc.NewAdminClient(conn),
		clusterClient: rpc.NewClusterClient(conn),
		md:            context.Background(),
	}

	return c, nil
}

type Client struct {
	conn          *grpc.ClientConn
	adminClient   rpc.AdminClient
	clusterClient rpc.ClusterClient
	md            context.Context
}

func NewClientWithStaticToken(pool *x509.CertPool, host string) (*Client, error) {
	overrideGrpcLogger()

	cred := credentials.NewClientTLSFromCert(pool, "")
	conn, err := grpc.Dial(fmt.Sprintf("%s", host), grpc.WithTransportCredentials(cred))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	adminClient := rpc.NewAdminClient(conn)

	tokenClient := token.NewTokenClient("token")
	t, err := tokenClient.GetToken()
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
		newToken, err := tokenClient.RequestToken(endpoint)
		ctx = metadata.AppendToOutgoingContext(context.Background(), rpc.TokenMetadataKey, newToken)
	}

	return &Client{
		conn:          conn,
		adminClient:   adminClient,
		clusterClient: rpc.NewClusterClient(conn),
		md:            ctx,
	}, nil
}

func (c *Client) Close() {
	c.conn.Close()
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

func (c *Client) ListCert() ([]*rpc.CertItem, error) {
	res, err := c.adminClient.CertList(c.md, &rpc.RequestCertList{})
	if err != nil {
		return nil, err
	}

	return res.Items, nil
}

func (c *Client) ListRevokedCert() ([]*rpc.CertItem, error) {
	res, err := c.adminClient.RevokedCertList(c.md, &rpc.RequestRevokedCertList{})
	if err != nil {
		return nil, err
	}

	return res.Items, nil
}

func (c *Client) NewCert(commonName, password, comment string) error {
	_, err := c.adminClient.CertNew(c.md, &rpc.RequestCertNew{CommonName: commonName, Password: password, Comment: comment})
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) NewAgentCert(commonName, comment string) error {
	_, err := c.adminClient.CertNew(c.md, &rpc.RequestCertNew{Agent: true, CommonName: commonName, Comment: comment})
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) RevokeCert(serialNumber *big.Int) error {
	_, err := c.adminClient.CertRevoke(c.md, &rpc.RequestCertRevoke{SerialNumber: serialNumber.Bytes()})
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) GetCert(serialNumber *big.Int) (*rpc.CertItem, error) {
	res, err := c.adminClient.CertGet(c.md, &rpc.RequestCertGet{SerialNumber: serialNumber.Bytes()})
	if err != nil {
		return nil, err
	}

	return res.Item, nil
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

func overrideGrpcLogger() {
	loggerOnce.Do(func() {
		grpc_zap.ReplaceGrpcLoggerV2(logger.Log)
	})
}
