package rpcclient

import (
	"context"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"go.f110.dev/heimdallr/pkg/rpc"
	"go.f110.dev/heimdallr/pkg/rpc/rpctestutil"
)

func TestNewWithClient(t *testing.T) {
	a := rpctestutil.NewAdminClient()
	cl := rpctestutil.NewClusterClient()
	ca := rpctestutil.NewCertificateAuthorityClient()
	user := rpctestutil.NewUserClient()
	c := NewWithClient(a, cl, ca, user)
	require.NotNil(t, c)

	ctx := context.Background()

	_ = c.AddUser(ctx, "", "")
	assert.Equal(t, 1, a.UserAddCall)
	_ = c.DeleteUser(ctx, "", "")
	assert.Equal(t, 1, a.UserDelCall)
	_, _ = c.ListAllUser(ctx)
	assert.Equal(t, 1, a.UserListCall)
	_, _ = c.ListServiceAccount(ctx)
	assert.Equal(t, 2, a.UserListCall)
	_, _ = c.ListUser(ctx, "")
	assert.Equal(t, 3, a.UserListCall)
	_ = c.NewServiceAccount(ctx, "", "")
	assert.Equal(t, 2, a.UserAddCall)
	_, _ = c.GetUser(ctx, "", false)
	assert.Equal(t, 1, a.UserGetCall)
	_ = c.UserBecomeMaintainer(ctx, "", "")
	assert.Equal(t, 1, a.BecomeMaintainerCall)
	_ = c.ToggleAdmin(ctx, "")
	assert.Equal(t, 1, a.ToggleAdminCall)
	_, _ = c.NewToken(ctx, "", "")
	assert.Equal(t, 1, a.TokenNewCall)
	_, _ = c.ListRole(ctx)
	assert.Equal(t, 1, a.RoleListCall)
	_, _ = c.ListAllBackend(ctx)
	assert.Equal(t, 1, a.BackendListCall)
	_, _ = c.ListAgentBackend(ctx)
	assert.Equal(t, 2, a.BackendListCall)

	_, _ = c.ClusterMemberList(ctx)
	assert.Equal(t, 1, cl.MemberListCall)
	_, _ = c.ListConnectedAgent(ctx)
	assert.Equal(t, 1, cl.AgentListCall)

	_, _ = c.ListCert(ctx)
	assert.Equal(t, 1, ca.GetSignedListCall)
	_, _ = c.ListRevokedCert(ctx)
	assert.Equal(t, 1, ca.GetRevokedListCall)
	_ = c.NewCert(ctx, "", "", 0, "", "")
	assert.Equal(t, 1, ca.NewClientCertCall)
	_, _ = c.NewCertByCSR(ctx, "")
	assert.Equal(t, 2, ca.NewClientCertCall)
	_ = c.NewAgentCert(ctx, "", "")
	assert.Equal(t, 3, ca.NewClientCertCall)
	_, _ = c.NewAgentCertByCSR(ctx, "", "'")
	assert.Equal(t, 4, ca.NewClientCertCall)
	_, _ = c.NewServerCert(ctx, []byte{})
	assert.Equal(t, 1, ca.NewServerCertCall)
	_ = c.RevokeCert(ctx, big.NewInt(0))
	assert.Equal(t, 1, ca.RevokeCall)
	_, _ = c.GetCert(ctx, big.NewInt(0))
	assert.Equal(t, 1, ca.GetCall)
}

func TestWithTokenKeepsTheCallerContext(t *testing.T) {
	a := rpctestutil.NewAdminClient()
	cl := rpctestutil.NewClusterClient()
	ca := rpctestutil.NewCertificateAuthorityClient()
	user := rpctestutil.NewUserClient()
	c := &ClientWithUserToken{Client: NewWithClient(a, cl, ca, user)}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = c.WithToken("token").ListAllUser(ctx)

	require.NotNil(t, a.UserListCtx)
	assert.ErrorIs(t, a.UserListCtx.Err(), context.Canceled)

	md, ok := metadata.FromOutgoingContext(a.UserListCtx)
	require.True(t, ok)
	assert.Equal(t, []string{"token"}, md.Get(rpc.JwtTokenMetadataKey))
}
