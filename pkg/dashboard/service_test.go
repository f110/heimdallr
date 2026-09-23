package dashboard

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"go.f110.dev/heimdallr/pkg/rpc"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
	"go.f110.dev/heimdallr/pkg/rpc/rpctestutil"
)

type mockClients struct {
	admin   *rpctestutil.AdminClient
	cluster *rpctestutil.ClusterClient
	ca      *rpctestutil.CertificateAuthorityClient
	user    *rpctestutil.UserClient
}

func newMockClients() (*mockClients, *rpcclient.ClientWithUserToken) {
	m := &mockClients{
		admin:   rpctestutil.NewAdminClient(),
		cluster: rpctestutil.NewClusterClient(),
		ca:      rpctestutil.NewCertificateAuthorityClient(),
		user:    rpctestutil.NewUserClient(),
	}

	return m, &rpcclient.ClientWithUserToken{Client: rpcclient.NewWithClient(m.admin, m.cluster, m.ca, m.user)}
}

// verifiedContext mimics what the auth interceptor puts into the context.
func verifiedContext(userId string) context.Context {
	ctx := context.WithValue(context.Background(), VerifiedUserIdKey, userId)
	return context.WithValue(ctx, UserTokenKey, "token")
}

func ts(sec int64) *timestamppb.Timestamp {
	return timestamppb.New(time.Unix(sec, 0))
}

func TestCertificateServiceListCertificates(t *testing.T) {
	m, c := newMockClients()
	m.ca.GetSignedListResponse = &rpc.ResponseGetSignedList{Items: []*rpc.CertItem{
		{SerialNumber: []byte{0x0a, 0xff}, CommonName: "old@example.com", IssuedAt: ts(100)},
		{SerialNumber: []byte{0x01}, CommonName: "agent", IssuedAt: ts(300), Agent: true},
		{SerialNumber: []byte{0x10}, CommonName: "new@example.com", IssuedAt: ts(200), HasP12: true},
	}}
	m.ca.GetRevokedListResponse = &rpc.ResponseGetRevokedList{Items: []*rpc.CertItem{
		{SerialNumber: []byte{0x02}, CommonName: "revoked@example.com", IssuedAt: ts(50), RevokedAt: ts(60)},
		{SerialNumber: []byte{0x03}, CommonName: "agent", IssuedAt: ts(50), RevokedAt: ts(70), Agent: true},
	}}

	res, err := NewCertificateService(c).ListCertificates(verifiedContext("admin@example.com"), connect.NewRequest(&ListCertificatesRequest{}))
	require.NoError(t, err)

	// The agent certificates belong to ListAgents and the newest certificate comes first.
	require.Len(t, res.Msg.Signed, 2)
	assert.Equal(t, "new@example.com", res.Msg.Signed[0].CommonName)
	assert.Equal(t, "10", res.Msg.Signed[0].SerialNumber)
	assert.True(t, res.Msg.Signed[0].HasP12)
	assert.Equal(t, "old@example.com", res.Msg.Signed[1].CommonName)
	assert.Equal(t, "aff", res.Msg.Signed[1].SerialNumber)
	assert.False(t, res.Msg.Signed[1].HasP12)

	require.Len(t, res.Msg.Revoked, 1)
	assert.Equal(t, "revoked@example.com", res.Msg.Revoked[0].CommonName)
}

func TestCertificateServiceListAgents(t *testing.T) {
	m, c := newMockClients()
	m.ca.GetSignedListResponse = &rpc.ResponseGetSignedList{Items: []*rpc.CertItem{
		{SerialNumber: []byte{0x01}, CommonName: "client@example.com", IssuedAt: ts(300)},
		{SerialNumber: []byte{0x02}, CommonName: "agent", IssuedAt: ts(200), Agent: true},
	}}
	m.cluster.AgentListResponse = &rpc.ResponseAgentList{Items: []*rpc.Agent{
		{Name: "agent", FromAddr: "10.0.0.1:1234", ConnectedAt: ts(400)},
	}}

	res, err := NewCertificateService(c).ListAgents(verifiedContext("admin@example.com"), connect.NewRequest(&ListAgentsRequest{}))
	require.NoError(t, err)

	require.Len(t, res.Msg.Signed, 1)
	assert.Equal(t, "agent", res.Msg.Signed[0].CommonName)
	require.Len(t, res.Msg.Connected, 1)
	assert.Equal(t, "10.0.0.1:1234", res.Msg.Connected[0].FromAddr)
}

func TestCertificateServiceNewClientCertificate(t *testing.T) {
	t.Run("CSR", func(t *testing.T) {
		m, c := newMockClients()

		_, err := NewCertificateService(c).NewClientCertificate(verifiedContext("admin@example.com"),
			connect.NewRequest(&NewClientCertificateRequest{Id: "foo@example.com", Csr: "-----BEGIN"}))
		require.NoError(t, err)

		require.NotNil(t, m.ca.NewClientCertRequest)
		assert.Equal(t, "-----BEGIN", m.ca.NewClientCertRequest.Csr)
		assert.Equal(t, "foo@example.com", m.ca.NewClientCertRequest.CommonName)
	})

	t.Run("KeyType", func(t *testing.T) {
		m, c := newMockClients()

		_, err := NewCertificateService(c).NewClientCertificate(verifiedContext("admin@example.com"),
			connect.NewRequest(&NewClientCertificateRequest{Id: "foo@example.com", KeyType: KeyType_KEY_TYPE_ECDSA, KeyBits: 256}))
		require.NoError(t, err)

		require.NotNil(t, m.ca.NewClientCertRequest)
		assert.Equal(t, "ecdsa", m.ca.NewClientCertRequest.KeyType)
		assert.Equal(t, int32(256), m.ca.NewClientCertRequest.KeyBits)
	})

	t.Run("UnknownKeyType", func(t *testing.T) {
		_, c := newMockClients()

		_, err := NewCertificateService(c).NewClientCertificate(verifiedContext("admin@example.com"),
			connect.NewRequest(&NewClientCertificateRequest{Id: "foo@example.com"}))
		require.Error(t, err)
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
	})
}

func TestCertificateServiceRevokeCertificate(t *testing.T) {
	m, c := newMockClients()

	_, err := NewCertificateService(c).RevokeCertificate(verifiedContext("admin@example.com"),
		connect.NewRequest(&RevokeCertificateRequest{SerialNumber: "aff"}))
	require.NoError(t, err)
	require.NotNil(t, m.ca.RevokeRequest)
	assert.Equal(t, []byte{0x0a, 0xff}, m.ca.RevokeRequest.SerialNumber)

	_, err = NewCertificateService(c).RevokeCertificate(verifiedContext("admin@example.com"),
		connect.NewRequest(&RevokeCertificateRequest{SerialNumber: "not a number"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestCertificateServiceListAgentBackends(t *testing.T) {
	m, c := newMockClients()
	m.admin.BackendListResponse = &rpc.ResponseBackendList{Items: []*rpc.BackendItem{
		{Name: "web", HttpBackends: []*rpc.HTTPBackend{{Path: "/"}, {Path: "/api"}}},
		{Name: "socket", SocketBackend: &rpc.SocketBackend{Agent: true}},
	}}

	res, err := NewCertificateService(c).ListAgentBackends(verifiedContext("admin@example.com"), connect.NewRequest(&ListAgentBackendsRequest{}))
	require.NoError(t, err)

	assert.Equal(t, []string{"web/", "web/api", "socket"}, res.Msg.Names)
	require.NotNil(t, m.admin.BackendListRequest)
	assert.True(t, m.admin.BackendListRequest.Agent)
}

func TestAdminServiceListUsers(t *testing.T) {
	m, c := newMockClients()
	m.admin.UserListResponse = &rpc.ResponseUserList{Items: []*rpc.UserItem{
		{Id: "b@example.com"},
		{Id: "z@example.com", Admin: true},
		{Id: "a@example.com", Type: rpc.UserType_SERVICE_ACCOUNT},
	}}

	res, err := NewAdminService(c).ListUsers(verifiedContext("admin@example.com"), connect.NewRequest(&ListUsersRequest{}))
	require.NoError(t, err)

	// Administrators come first, then sorted by the id.
	require.Len(t, res.Msg.Users, 3)
	assert.Equal(t, "z@example.com", res.Msg.Users[0].Id)
	assert.Equal(t, "a@example.com", res.Msg.Users[1].Id)
	assert.Equal(t, UserType_USER_TYPE_SERVICE_ACCOUNT, res.Msg.Users[1].Type)
	assert.Equal(t, "b@example.com", res.Msg.Users[2].Id)
	assert.Equal(t, UserType_USER_TYPE_NORMAL, res.Msg.Users[2].Type)
}

// GetUser resolves the backends that the user can reach through the roles.
func TestAdminServiceGetUser(t *testing.T) {
	m, c := newMockClients()
	m.admin.UserGetResponse = &rpc.ResponseUserGet{User: &rpc.UserItem{
		Id:    "foo@example.com",
		Roles: []string{"admin", "unknown"},
	}}
	m.admin.RoleListResponse = &rpc.ResponseRoleList{Items: []*rpc.RoleItem{
		{Name: "admin", Backends: []string{"dashboard", "missing"}},
		{Name: "other", Backends: []string{"secret"}},
	}}
	m.admin.BackendListResponse = &rpc.ResponseBackendList{Items: []*rpc.BackendItem{
		{Name: "dashboard", Host: "dashboard.example.com"},
		{Name: "secret", Host: "secret.example.com"},
	}}

	res, err := NewAdminService(c).GetUser(verifiedContext("admin@example.com"), connect.NewRequest(&GetUserRequest{Id: "foo@example.com"}))
	require.NoError(t, err)

	assert.Equal(t, "foo@example.com", res.Msg.User.Id)
	require.Len(t, res.Msg.Backends, 1)
	assert.Equal(t, "dashboard.example.com", res.Msg.Backends[0].Host)
}

func TestAdminServiceGetUserRequiresId(t *testing.T) {
	_, c := newMockClients()

	_, err := NewAdminService(c).GetUser(verifiedContext("admin@example.com"), connect.NewRequest(&GetUserRequest{}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

// UpdateUser reads the user first so that the other fields are not lost.
func TestAdminServiceUpdateUser(t *testing.T) {
	m, c := newMockClients()
	m.admin.UserGetResponse = &rpc.ResponseUserGet{User: &rpc.UserItem{
		Id:        "foo@example.com",
		Roles:     []string{"admin"},
		LoginName: "old",
	}}

	_, err := NewAdminService(c).UpdateUser(verifiedContext("admin@example.com"),
		connect.NewRequest(&UpdateUserRequest{Id: "foo@example.com", LoginName: "new"}))
	require.NoError(t, err)

	require.NotNil(t, m.admin.UserEditRequest)
	assert.Equal(t, "foo@example.com", m.admin.UserEditRequest.Id)
	assert.Equal(t, "new", m.admin.UserEditRequest.User.LoginName)
	assert.Equal(t, []string{"admin"}, m.admin.UserEditRequest.User.Roles)
}

func TestAdminServiceListRoles(t *testing.T) {
	m, c := newMockClients()
	m.admin.UserListResponse = &rpc.ResponseUserList{Items: []*rpc.UserItem{
		{Id: "z@example.com", Roles: []string{"admin"}},
		{Id: "a@example.com", Roles: []string{"admin"}, MaintainRoles: []string{"admin"}},
		{Id: "s@example.com", Roles: []string{"system"}},
	}}
	m.admin.RoleListResponse = &rpc.ResponseRoleList{Items: []*rpc.RoleItem{
		{Name: "admin", Title: "Administrator"},
		{Name: "system", System: true},
	}}

	res, err := NewAdminService(c).ListRoles(verifiedContext("admin@example.com"), connect.NewRequest(&ListRolesRequest{}))
	require.NoError(t, err)

	// The system role is not manageable.
	require.Len(t, res.Msg.Roles, 1)
	assert.Equal(t, "Administrator", res.Msg.Roles[0].Role.Title)
	require.Len(t, res.Msg.Roles[0].Members, 2)
	assert.Equal(t, "a@example.com", res.Msg.Roles[0].Members[0].Id)
	assert.True(t, res.Msg.Roles[0].Members[0].Maintainer)
	assert.Equal(t, "z@example.com", res.Msg.Roles[0].Members[1].Id)
	assert.False(t, res.Msg.Roles[0].Members[1].Maintainer)
}

func TestMeServiceGetMe(t *testing.T) {
	m, c := newMockClients()
	m.ca.GetSignedListResponse = &rpc.ResponseGetSignedList{Items: []*rpc.CertItem{
		{SerialNumber: []byte{0x01}, Comment: "laptop", IssuedAt: ts(100), Device: true},
		{SerialNumber: []byte{0x02}, Comment: "phone", IssuedAt: ts(200), Device: true},
	}}
	m.user.GetBackendsResponse = &rpc.ResponseGetBackends{Items: []*rpc.BackendItem{
		{Name: "web", Host: "web.example.com", Description: "Web"},
	}}

	res, err := NewMeService(c).GetMe(verifiedContext("foo@example.com"), connect.NewRequest(&GetMeRequest{}))
	require.NoError(t, err)

	require.Len(t, res.Msg.Devices, 2)
	assert.Equal(t, "phone", res.Msg.Devices[0].Comment)
	assert.Equal(t, "laptop", res.Msg.Devices[1].Comment)
	require.Len(t, res.Msg.Backends, 1)
	assert.Equal(t, "web.example.com", res.Msg.Backends[0].Host)
}

// AddDevice always overrides the common name with the subject of the verified token.
func TestMeServiceAddDevice(t *testing.T) {
	m, c := newMockClients()

	_, err := NewMeService(c).AddDevice(verifiedContext("foo@example.com"),
		connect.NewRequest(&AddDeviceRequest{Name: "laptop", Csr: "-----BEGIN"}))
	require.NoError(t, err)

	require.NotNil(t, m.ca.NewClientCertRequest)
	assert.Equal(t, "foo@example.com", m.ca.NewClientCertRequest.OverrideCommonName)
	assert.Equal(t, "laptop", m.ca.NewClientCertRequest.Comment)
	assert.True(t, m.ca.NewClientCertRequest.Device)
}

func TestMeServiceAddDeviceRequiresCsr(t *testing.T) {
	_, c := newMockClients()

	_, err := NewMeService(c).AddDevice(verifiedContext("foo@example.com"), connect.NewRequest(&AddDeviceRequest{Name: "laptop"}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestServiceRequiresVerifiedUser(t *testing.T) {
	_, c := newMockClients()

	_, err := NewMeService(c).GetMe(context.Background(), connect.NewRequest(&GetMeRequest{}))
	require.Error(t, err)
	assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
}
