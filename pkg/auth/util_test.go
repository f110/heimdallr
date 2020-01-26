package auth

import (
	"os"
	"testing"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc/rpcclient"
)

func TestMain(m *testing.M) {
	logger.Init(&config.Logger{Level: "debug"})

	os.Exit(m.Run())
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
