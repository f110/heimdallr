package rpcclient

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.f110.dev/heimdallr/pkg/rpc/rpctestutil"
)

func TestNewWithClient(t *testing.T) {
	a := rpctestutil.NewAdminClient()
	cl := rpctestutil.NewClusterClient()
	ca := rpctestutil.NewCertificateAuthorityClient()
	user := rpctestutil.NewUserClient()
	c := NewWithClient(a, cl, ca, user)
	require.NotNil(t, c)

	_ = c.AddUser("", "")
	assert.Equal(t, 1, a.UserAddCall)
	_ = c.DeleteUser("", "")
	assert.Equal(t, 1, a.UserDelCall)
	_, _ = c.ListAllUser()
	assert.Equal(t, 1, a.UserListCall)
	_, _ = c.ListServiceAccount()
	assert.Equal(t, 2, a.UserListCall)
	_, _ = c.ListUser("")
	assert.Equal(t, 3, a.UserListCall)
	_ = c.NewServiceAccount("", "")
	assert.Equal(t, 2, a.UserAddCall)
	_, _ = c.GetUser("", false)
	assert.Equal(t, 1, a.UserGetCall)
	_ = c.UserBecomeMaintainer("", "")
	assert.Equal(t, 1, a.BecomeMaintainerCall)
	_ = c.ToggleAdmin("")
	assert.Equal(t, 1, a.ToggleAdminCall)
	_, _ = c.NewToken("", "")
	assert.Equal(t, 1, a.TokenNewCall)
	_, _ = c.ListRole()
	assert.Equal(t, 1, a.RoleListCall)
	_, _ = c.ListAllBackend()
	assert.Equal(t, 1, a.BackendListCall)
	_, _ = c.ListAgentBackend()
	assert.Equal(t, 2, a.BackendListCall)

	_, _ = c.ClusterMemberList()
	assert.Equal(t, 1, cl.MemberListCall)
	_, _ = c.ListConnectedAgent()
	assert.Equal(t, 1, cl.AgentListCall)

	_, _ = c.ListCert()
	assert.Equal(t, 1, ca.GetSignedListCall)
	_, _ = c.ListRevokedCert()
	assert.Equal(t, 1, ca.GetRevokedListCall)
	_ = c.NewCert("", "", 0, "", "")
	assert.Equal(t, 1, ca.NewClientCertCall)
	_, _ = c.NewCertByCSR("")
	assert.Equal(t, 2, ca.NewClientCertCall)
	_ = c.NewAgentCert("", "")
	assert.Equal(t, 3, ca.NewClientCertCall)
	_, _ = c.NewAgentCertByCSR("", "'")
	assert.Equal(t, 4, ca.NewClientCertCall)
	_, _ = c.NewServerCert([]byte{})
	assert.Equal(t, 1, ca.NewServerCertCall)
	_ = c.RevokeCert(big.NewInt(0))
	assert.Equal(t, 1, ca.RevokeCall)
	_, _ = c.GetCert(big.NewInt(0))
	assert.Equal(t, 1, ca.GetCall)
}
