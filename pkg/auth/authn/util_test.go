package authn

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
)

func TestMain(m *testing.M) {
	logger.Init(&configv2.Logger{Level: "debug"})

	m.Run()
}

type testRevokedCertClient struct {
	revokedCert []*rpcclient.RevokedCert
}

func NewRevokedCertClient() *testRevokedCertClient {
	return &testRevokedCertClient{revokedCert: make([]*rpcclient.RevokedCert, 0)}
}

func (r *testRevokedCertClient) Get() []*rpcclient.RevokedCert {
	return r.revokedCert
}

type testServerStream struct {
	ctx context.Context
}

func (t *testServerStream) SetHeader(metadata.MD) error {
	panic("implement me")
}

func (t *testServerStream) SendHeader(metadata.MD) error {
	panic("implement me")
}

func (t *testServerStream) SetTrailer(metadata.MD) {
	panic("implement me")
}

func (t *testServerStream) Context() context.Context {
	return t.ctx
}

func (t *testServerStream) SendMsg(m interface{}) error {
	panic("implement me")
}

func (t *testServerStream) RecvMsg(m interface{}) error {
	panic("implement me")
}
