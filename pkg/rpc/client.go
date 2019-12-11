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
	conn   *grpc.ClientConn
	client AdminClient
	md     context.Context
}

func NewClient(pool *x509.CertPool, host string) (*Client, error) {
	cred := credentials.NewClientTLSFromCert(pool, "")
	conn, err := grpc.Dial(fmt.Sprintf("%s", host), grpc.WithTransportCredentials(cred))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	client := NewAdminClient(conn)

	tokenClient := token.NewTokenClient("token")
	t, err := tokenClient.GetToken()
	if err != nil {
		return nil, xerrors.Errorf(": %v", nil)
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), TokenMetadataKey, t)
	_, err = client.Ping(ctx, &RequestPing{})
	if err != nil {
		endpoint, err := extractEndpointFromError(err)
		if err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}
		newToken, err := tokenClient.RequestToken(endpoint)
		ctx = metadata.AppendToOutgoingContext(context.Background(), TokenMetadataKey, newToken)
	}

	return &Client{conn: conn, client: client, md: ctx}, nil
}

func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) AddUser(id string, role string) error {
	_, err := c.client.UserAdd(c.md, &RequestUserAdd{Id: id, Role: role})
	return err
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
