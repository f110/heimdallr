package rpcserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"

	"go.f110.dev/heimdallr/pkg/auth"
	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/database/memory"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/netutil"
	"go.f110.dev/heimdallr/pkg/rpc"
)

func TestNewServer(t *testing.T) {
	conf := &configv2.Config{
		CertificateAuthority: &configv2.CertificateAuthority{},
		RPCServer: &configv2.RPCServer{
			Bind: ":0",
		},
		Logger: &configv2.Logger{
			Level: "error",
		},
	}
	err := logger.Init(conf.Logger)
	require.NoError(t, err)

	v := NewServer(
		conf,
		memory.NewUserDatabase(),
		memory.NewTokenDatabase(),
		memory.NewClusterDatabase(),
		memory.NewRelayLocator(),
		cert.NewCertificateAuthority(memory.NewCA(), conf.CertificateAuthority),
		nil,
	)
	require.NotNil(t, v)
}

func TestServer_Start(t *testing.T) {
	caCert, caPrivateKey, err := cert.CreateCertificateAuthority("test", "test", "test", "jp")
	require.NoError(t, err)
	port, err := netutil.FindUnusedPort()
	require.NoError(t, err)
	metricPort, err := netutil.FindUnusedPort()
	require.NoError(t, err)

	conf := &configv2.Config{
		CertificateAuthority: &configv2.CertificateAuthority{
			Local: &configv2.CertificateAuthorityLocal{
				Certificate: caCert,
				PrivateKey:  caPrivateKey,
			},
		},
		RPCServer: &configv2.RPCServer{
			Bind:        fmt.Sprintf(":%d", port),
			MetricsBind: fmt.Sprintf(":%d", metricPort),
		},
		Logger: &configv2.Logger{
			Level: "error",
		},
	}
	err = logger.Init(conf.Logger)
	require.NoError(t, err)

	v := NewServer(
		conf,
		memory.NewUserDatabase(),
		memory.NewTokenDatabase(),
		memory.NewClusterDatabase(),
		memory.NewRelayLocator(),
		cert.NewCertificateAuthority(memory.NewCA(), conf.CertificateAuthority),
		nil,
	)
	go func() {
		err := v.Start()
		require.NoError(t, err)
	}()

	err = netutil.WaitListen(fmt.Sprintf(":%d", port), 5*time.Second)
	require.NoError(t, err)
	err = netutil.WaitListen(fmt.Sprintf(":%d", metricPort), 5*time.Second)
	require.NoError(t, err)

	err = v.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestServicesViaServer(t *testing.T) {
	hostname, err := os.Hostname()
	require.NoError(t, err)
	caCert, caPrivateKey, err := cert.CreateCertificateAuthority("test", "test", "test", "jp")
	require.NoError(t, err)
	port, err := netutil.FindUnusedPort()
	require.NoError(t, err)
	signReqKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signReqPubKey := signReqKey.PublicKey

	conf := &configv2.Config{
		AccessProxy: &configv2.AccessProxy{
			ServerNameHost: "test.example.com",
			Credential: &configv2.Credential{
				InternalToken:     "internal-token",
				SigningPrivateKey: signReqKey,
				SigningPublicKey:  signReqPubKey,
			},
			Backends: []*configv2.Backend{
				{Name: "test", Agent: true},
			},
		},
		CertificateAuthority: &configv2.CertificateAuthority{
			Local: &configv2.CertificateAuthorityLocal{
				Certificate: caCert,
				PrivateKey:  caPrivateKey,
			},
		},
		AuthorizationEngine: &configv2.AuthorizationEngine{
			RootUsers: []string{database.SystemUser.Id},
			Roles: []*configv2.Role{
				{
					Name: "test-admin",
					Bindings: []*configv2.Binding{
						{RPC: "test-admin"},
					},
				},
				{Name: "test-admin2"},
			},
			RPCPermissions: []*configv2.RPCPermission{
				{Name: "test-admin", Allow: []string{"/proxy.rpc.Admin/*"}},
			},
		},
		RPCServer: &configv2.RPCServer{
			Bind: fmt.Sprintf(":%d", port),
		},
		Logger: &configv2.Logger{
			Level: "error",
		},
	}
	err = conf.AccessProxy.Setup(conf.AccessProxy.Backends)
	require.NoError(t, err)
	err = conf.AuthorizationEngine.Setup(conf.AuthorizationEngine.Roles, conf.AuthorizationEngine.RPCPermissions)
	require.NoError(t, err)
	err = logger.Init(conf.Logger)
	require.NoError(t, err)
	u := memory.NewUserDatabase(database.SystemUser)
	token := memory.NewTokenDatabase()
	cluster := memory.NewClusterDatabase()
	relay := memory.NewRelayLocator()
	auth.Init(conf, nil, u, token, nil)

	testUser := &database.User{
		Id:    "test@example.com",
		Type:  database.UserTypeNormal,
		Roles: []string{"test-admin"},
	}
	testUser.Setup()
	err = u.Set(nil, testUser)
	require.NoError(t, err)
	code, err := token.NewCode(nil, testUser.Id, "", "")
	require.NoError(t, err)
	userToken, err := token.IssueToken(nil, code.Code, "")
	require.NoError(t, err)

	_ = cluster.Join(nil)
	_ = relay.Set(context.Background(), &database.Relay{Name: "test", Addr: "127.0.0.1:10000"})

	s := NewServer(
		conf,
		u,
		token,
		cluster,
		relay,
		cert.NewCertificateAuthority(memory.NewCA(), conf.CertificateAuthority),
		func() bool { return true },
	)
	go func() {
		err := s.Start()
		require.NoError(t, err)
	}()
	err = netutil.WaitListen(fmt.Sprintf(":%d", port), 5*time.Second)
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	transCreds := credentials.NewTLS(&tls.Config{
		ServerName: rpc.ServerHostname,
		RootCAs:    caPool,
	})
	conn, err := grpc.Dial(fmt.Sprintf(":%d", port), grpc.WithTransportCredentials(transCreds))
	require.NoError(t, err)

	md := metadata.New(map[string]string{rpc.InternalTokenMetadataKey: "internal-token"})
	systemUserCtx := metadata.NewOutgoingContext(context.Background(), md)

	md = metadata.New(map[string]string{rpc.TokenMetadataKey: userToken.Token})
	testUserCtx := metadata.NewOutgoingContext(context.Background(), md)

	t.Run("Admin", func(t *testing.T) {
		t.Parallel()

		adminClient := rpc.NewAdminClient(conn)
		res, err := adminClient.Ping(context.Background(), &rpc.RequestPing{})
		require.NoError(t, err)
		assert.NotNil(t, res)

		t.Run("Get Config", func(t *testing.T) {
			backendListRes, err := adminClient.BackendList(systemUserCtx, &rpc.RequestBackendList{})
			require.NoError(t, err)
			assert.Len(t, backendListRes.GetItems(), 1)

			roleListRes, err := adminClient.RoleList(systemUserCtx, &rpc.RequestRoleList{})
			require.NoError(t, err)
			assert.Len(t, roleListRes.GetItems(), 3)
		})

		t.Run("Management User", func(t *testing.T) {
			t.Parallel()

			addRes, err := adminClient.UserAdd(systemUserCtx, &rpc.RequestUserAdd{
				Id:   testUser.Id,
				Type: rpc.UserType_NORMAL,
				Role: "test-admin2",
			})
			require.NoError(t, err)
			assert.True(t, addRes.GetOk())

			getRes, err := adminClient.UserGet(systemUserCtx, &rpc.RequestUserGet{Id: testUser.Id, WithTokens: true})
			require.NoError(t, err)
			assert.Equal(t, "test@example.com", getRes.GetUser().GetId())
			assert.Equal(t, "test-admin", getRes.GetUser().GetRoles()[0])
			assert.Equal(t, "test-admin2", getRes.GetUser().GetRoles()[1])
			assert.Equal(t, rpc.UserType_NORMAL, getRes.GetUser().GetType())

			becomeRes, err := adminClient.BecomeMaintainer(systemUserCtx, &rpc.RequestBecomeMaintainer{Id: testUser.Id, Role: "test-admin"})
			require.NoError(t, err)
			assert.True(t, becomeRes.GetOk())

			getRes, err = adminClient.UserGet(systemUserCtx, &rpc.RequestUserGet{Id: "test@example.com"})
			require.NoError(t, err)
			assert.Len(t, getRes.GetUser().GetMaintainRoles(), 1)

			userListRes, err := adminClient.UserList(systemUserCtx, &rpc.RequestUserList{})
			require.NoError(t, err)
			assert.Len(t, userListRes.GetItems(), 2)
			userListRes, err = adminClient.UserList(systemUserCtx, &rpc.RequestUserList{Role: "test-admin"})
			require.NoError(t, err)
			assert.Len(t, userListRes.GetItems(), 1)
			userListRes, err = adminClient.UserList(systemUserCtx, &rpc.RequestUserList{ServiceAccount: true})
			require.NoError(t, err)
			assert.Len(t, userListRes.GetItems(), 1)

			toggleRes, err := adminClient.ToggleAdmin(systemUserCtx, &rpc.RequestToggleAdmin{Id: testUser.Id})
			require.NoError(t, err)
			assert.True(t, toggleRes.GetOk())
			userListRes, err = adminClient.UserList(testUserCtx, &rpc.RequestUserList{})
			require.NoError(t, err)
			assert.Len(t, userListRes.GetItems(), 2)

			tokenRes, err := adminClient.TokenNew(systemUserCtx, &rpc.RequestTokenNew{Name: "test", UserId: testUser.Id})
			require.NoError(t, err)
			assert.NotEmpty(t, tokenRes.GetItem().GetValue())
			getRes, err = adminClient.UserGet(systemUserCtx, &rpc.RequestUserGet{Id: testUser.Id, WithTokens: true})
			require.NoError(t, err)
			assert.Len(t, getRes.GetUser().GetTokens(), 1)
			assert.Equal(t, "test", getRes.GetUser().GetTokens()[0].GetName())
			assert.Equal(t, database.SystemUser.Id, getRes.GetUser().GetTokens()[0].GetIssuer())
		})
	})

	t.Run("CertificateAuthority", func(t *testing.T) {
		t.Parallel()

		caClient := rpc.NewCertificateAuthorityClient(conn)

		newRes, err := caClient.NewClientCert(systemUserCtx, &rpc.RequestNewClientCert{
			CommonName: "test@example.com",
			Comment:    "for test",
			KeyType:    "rsa",
			KeyBits:    2048,
			Password:   "test",
		})
		require.NoError(t, err)
		require.True(t, newRes.GetOk())

		csr, _, err := cert.CreatePrivateKeyAndCertificateRequest(pkix.Name{CommonName: "csr@example.com"}, []string{})
		require.NoError(t, err)
		newRes, err = caClient.NewClientCert(systemUserCtx, &rpc.RequestNewClientCert{
			Csr:        string(csr),
			CommonName: "csr@example.com",
		})
		require.NoError(t, err)
		require.True(t, newRes.GetOk())

		newRes, err = caClient.NewClientCert(systemUserCtx, &rpc.RequestNewClientCert{
			Agent:      true,
			CommonName: "test",
		})
		require.NoError(t, err)
		require.True(t, newRes.GetOk())

		signedListRes, err := caClient.GetSignedList(systemUserCtx, &rpc.RequestGetSignedList{})
		require.NoError(t, err)
		assert.Len(t, signedListRes.Items, 3)

		revokedCert, err := caClient.Get(systemUserCtx, &rpc.CARequestGet{SerialNumber: signedListRes.Items[0].SerialNumber})
		require.NoError(t, err)
		assert.NotNil(t, revokedCert.Item)

		revokeRes, err := caClient.Revoke(systemUserCtx, &rpc.CARequestRevoke{SerialNumber: revokedCert.Item.SerialNumber})
		require.NoError(t, err)
		assert.True(t, revokeRes.GetOk())
		revokedListRes, err := caClient.GetRevokedList(systemUserCtx, &rpc.RequestGetRevokedList{})
		require.NoError(t, err)
		assert.Len(t, revokedListRes.GetItems(), 1)

		csr, _, err = cert.CreatePrivateKeyAndCertificateRequest(pkix.Name{CommonName: "test.example.com"}, []string{"test.example.com"})
		require.NoError(t, err)
		newServerCertRes, err := caClient.NewServerCert(systemUserCtx, &rpc.RequestNewServerCert{SigningRequest: csr})
		require.NoError(t, err)
		assert.NotEqual(t, 0, len(newServerCertRes.Certificate))
	})

	t.Run("Cluster", func(t *testing.T) {
		t.Parallel()

		clusterClient := rpc.NewClusterClient(conn)

		memberListRes, err := clusterClient.MemberList(systemUserCtx, &rpc.RequestMemberList{})
		require.NoError(t, err)
		assert.Len(t, memberListRes.GetItems(), 1)
		assert.Equal(t, hostname, memberListRes.GetItems()[0].GetId())

		memberStatRes, err := clusterClient.MemberStat(systemUserCtx, &rpc.RequestMemberStat{})
		require.NoError(t, err)
		require.Equal(t, cluster.Id(), memberStatRes.GetId())
		assert.Equal(t, int32(2), memberStatRes.GetUserCount())
		assert.Equal(t, int32(1), memberStatRes.GetTokenCount())
		assert.Len(t, memberStatRes.GetListenedRelayAddrs(), 1)

		agentListRes, err := clusterClient.AgentList(systemUserCtx, &rpc.RequestAgentList{})
		require.NoError(t, err)
		require.Len(t, agentListRes.GetItems(), 1)
		assert.Equal(t, "test", agentListRes.GetItems()[0].GetName())
	})

	t.Run("Health", func(t *testing.T) {
		t.Parallel()

		healthClient := healthpb.NewHealthClient(conn)

		checkRes, err := healthClient.Check(systemUserCtx, &healthpb.HealthCheckRequest{})
		require.NoError(t, err)
		assert.Equal(t, healthpb.HealthCheckResponse_SERVING, checkRes.Status)
	})
}
