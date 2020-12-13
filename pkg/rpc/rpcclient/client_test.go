package rpcclient

import (
	"math/big"
	"testing"

	"go.f110.dev/heimdallr/pkg/rpc/rpctestutil"
)

func TestNewWithClient(t *testing.T) {
	a := rpctestutil.NewAdminClient()
	cl := rpctestutil.NewClusterClient()
	ca := rpctestutil.NewCertificateAuthorityClient()
	u := rpctestutil.NewUserClient()
	c := NewWithClient(a, cl, ca, u)
	if c == nil {
		t.Fatal("NewWithClient should return a value")
	}

	_ = c.AddUser("", "")
	if a.UserAddCall != 1 {
		t.Error("Expect call UserAdd")
	}
	_ = c.DeleteUser("", "")
	if a.UserDelCall != 1 {
		t.Error("Expect call UserDel")
	}
	_, _ = c.ListAllUser()
	if a.UserListCall != 1 {
		t.Error("Expect call UserList")
	}
	_, _ = c.ListServiceAccount()
	if a.UserListCall != 2 {
		t.Error("Expect call UserList")
	}
	_, _ = c.ListUser("")
	if a.UserListCall != 3 {
		t.Error("Expect call UserList")
	}
	_ = c.NewServiceAccount("", "")
	if a.UserAddCall != 2 {
		t.Error("Expect call UserAdd")
	}
	_, _ = c.GetUser("", false)
	if a.UserGetCall != 1 {
		t.Error("Expect call UserGet")
	}
	_ = c.UserBecomeMaintainer("", "")
	if a.BecomeMaintainerCall != 1 {
		t.Error("Expect call BecomeMaintainer")
	}
	_ = c.ToggleAdmin("")
	if a.ToggleAdminCall != 1 {
		t.Error("Expect call ToggleAdmin")
	}
	_, _ = c.NewToken("", "")
	if a.TokenNewCall != 1 {
		t.Error("Expect call TokenNew")
	}
	_, _ = c.ListRole()
	if a.RoleListCall != 1 {
		t.Error("Expect call RoleList")
	}
	_, _ = c.ListAllBackend()
	if a.BackendListCall != 1 {
		t.Error("Expect call BackendList")
	}
	_, _ = c.ListAgentBackend()
	if a.BackendListCall != 2 {
		t.Error("Expect call BackendList")
	}

	_, _ = c.ClusterMemberList()
	if cl.MemberListCall != 1 {
		t.Error("Expect call MemberList")
	}
	_, _ = c.ListConnectedAgent()
	if cl.AgentListCall != 1 {
		t.Error("Expect call AgentList")
	}

	_, _ = c.ListCert()
	if ca.GetSignedListCall != 1 {
		t.Error("Expect call GetSignedList")
	}
	_, _ = c.ListRevokedCert()
	if ca.GetRevokedListCall != 1 {
		t.Error("Expect call ListRevokedCert")
	}
	_ = c.NewCert("", "", 0, "", "")
	if ca.NewClientCertCall != 1 {
		t.Error("Expect call NewClientCert")
	}
	_, _ = c.NewCertByCSR("", "")
	if ca.NewClientCertCall != 2 {
		t.Error("Expect call NewClientCert")
	}
	_ = c.NewAgentCert("", "")
	if ca.NewClientCertCall != 3 {
		t.Error("Expect call NewClientCert")
	}
	_, _ = c.NewAgentCertByCSR("", "'")
	if ca.NewClientCertCall != 4 {
		t.Error("Expect call NewClientCert")
	}
	_, _ = c.NewServerCert([]byte{})
	if ca.NewServerCertCall != 1 {
		t.Error("Expect call NewServerCert")
	}
	_ = c.RevokeCert(big.NewInt(0))
	if ca.RevokeCall != 1 {
		t.Error("Expect call Revoke")
	}
	_, _ = c.GetCert(big.NewInt(0))
	if ca.GetCall != 1 {
		t.Error("Expect call Get")
	}
}
