package rpc

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/f110/lagrangian-proxy/pkg/auth/token"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Client struct {
	conn          *grpc.ClientConn
	adminClient   AdminClient
	clusterClient ClusterClient
	md            context.Context
}

func NewClient(pool *x509.CertPool, host string) (*Client, error) {
	cred := credentials.NewClientTLSFromCert(pool, "")
	conn, err := grpc.Dial(fmt.Sprintf("%s", host), grpc.WithTransportCredentials(cred))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	adminClient := NewAdminClient(conn)

	tokenClient := token.NewTokenClient("token")
	t, err := tokenClient.GetToken()
	if err != nil {
		return nil, xerrors.Errorf(": %v", nil)
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), TokenMetadataKey, t)
	_, err = adminClient.Ping(ctx, &RequestPing{})
	if err != nil {
		endpoint, err := extractEndpointFromError(err)
		if err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}
		newToken, err := tokenClient.RequestToken(endpoint)
		ctx = metadata.AppendToOutgoingContext(context.Background(), TokenMetadataKey, newToken)
	}

	return &Client{
		conn:          conn,
		adminClient:   adminClient,
		clusterClient: NewClusterClient(conn),
		md:            ctx,
	}, nil
}

func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) AddUser(id string, role string) error {
	_, err := c.adminClient.UserAdd(c.md, &RequestUserAdd{Id: id, Role: role})
	return err
}

func (c *Client) DeleteUser(id string, role string) error {
	_, err := c.adminClient.UserDel(c.md, &RequestUserDel{Id: id, Role: role})
	return err
}

func (c *Client) ListAllUser() ([]*UserItem, error) {
	return c.ListUser("")
}

func (c *Client) ListUser(role string) ([]*UserItem, error) {
	res, err := c.adminClient.UserList(c.md, &RequestUserList{Role: role})
	if err != nil {
		return nil, err
	}

	return res.Items, nil
}

func (c *Client) ClusterMemberList() ([]*ClusterMember, error) {
	res, err := c.clusterClient.MemberList(c.md, &RequestMemberList{})
	if err != nil {
		return nil, err
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

	if v, ok := e.Details()[0].(*ErrorUnauthorized); ok {
		return v.Endpoint, nil
	}

	return "", err
}
