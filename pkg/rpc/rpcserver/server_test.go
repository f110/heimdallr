package rpcserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"

	"github.com/f110/lagrangian-proxy/pkg/auth"
	"github.com/f110/lagrangian-proxy/pkg/cert"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/database/memory"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/netutil"
	"github.com/f110/lagrangian-proxy/pkg/rpc"
)

func TestNewServer(t *testing.T) {
	conf := &config.Config{
		General: &config.General{
			CertificateAuthority: &config.CertificateAuthority{},
		},
		RPCServer: &config.RPCServer{
			Bind: ":0",
		},
		Logger: &config.Logger{
			Level: "error",
		},
	}
	if err := logger.Init(conf.Logger); err != nil {
		t.Fatal(err)
	}

	v := NewServer(
		conf,
		memory.NewUserDatabase(),
		memory.NewTokenDatabase(),
		memory.NewClusterDatabase(),
		memory.NewRelayLocator(),
		memory.NewCA(conf.General.CertificateAuthority),
		nil,
	)
	if v == nil {
		t.Fatal("NewServer should return a value")
	}
}

func TestServer_Start(t *testing.T) {
	caCert, caPrivateKey, err := cert.CreateCertificateAuthority("test", "test", "test", "jp")
	if err != nil {
		t.Fatal(err)
	}
	port, err := netutil.FindUnusedPort()
	if err != nil {
		t.Fatal(err)
	}
	metricPort, err := netutil.FindUnusedPort()
	if err != nil {
		t.Fatal(err)
	}

	conf := &config.Config{
		General: &config.General{
			CertificateAuthority: &config.CertificateAuthority{
				Certificate: caCert,
				PrivateKey:  caPrivateKey,
			},
		},
		RPCServer: &config.RPCServer{
			Bind:        fmt.Sprintf(":%d", port),
			MetricsBind: fmt.Sprintf(":%d", metricPort),
		},
		Logger: &config.Logger{
			Level: "error",
		},
	}
	if err := logger.Init(conf.Logger); err != nil {
		t.Fatal(err)
	}

	v := NewServer(
		conf,
		memory.NewUserDatabase(),
		memory.NewTokenDatabase(),
		memory.NewClusterDatabase(),
		memory.NewRelayLocator(),
		memory.NewCA(conf.General.CertificateAuthority),
		nil,
	)
	go func() {
		if err := v.Start(); err != nil {
			t.Fatal(err)
		}
	}()

	if err := netutil.WaitListen(fmt.Sprintf(":%d", port), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := netutil.WaitListen(fmt.Sprintf(":%d", metricPort), 5*time.Second); err != nil {
		t.Fatal(err)
	}

	if err := v.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestServicesViaServer(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	caCert, caPrivateKey, err := cert.CreateCertificateAuthority("test", "test", "test", "jp")
	if err != nil {
		t.Fatal(err)
	}
	port, err := netutil.FindUnusedPort()
	if err != nil {
		t.Fatal(err)
	}
	signReqKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signReqPubKey := signReqKey.PublicKey

	conf := &config.Config{
		General: &config.General{
			ServerNameHost: "test.example.com",
			CertificateAuthority: &config.CertificateAuthority{
				Certificate: caCert,
				PrivateKey:  caPrivateKey,
			},
			InternalToken:     "internal-token",
			RootUsers:         []string{database.SystemUser.Id},
			SigningPrivateKey: signReqKey,
			SigningPublicKey:  signReqPubKey,
			Backends: []*config.Backend{
				{Name: "test", Agent: true},
			},
			Roles: []*config.Role{
				{
					Name: "test-admin",
					Bindings: []*config.Binding{
						{Rpc: "test-admin"},
					},
				},
				{Name: "test-admin2"},
			},
			RpcPermissions: []*config.RpcPermission{
				{Name: "test-admin", Allow: []string{"/proxy.rpc.Admin/*"}},
			},
		},
		RPCServer: &config.RPCServer{
			Bind: fmt.Sprintf(":%d", port),
		},
		Logger: &config.Logger{
			Level: "error",
		},
	}
	if err := conf.General.Load(conf.General.Backends, conf.General.Roles, conf.General.RpcPermissions); err != nil {
		t.Fatal(err)
	}
	if err := logger.Init(conf.Logger); err != nil {
		t.Fatal(err)
	}
	u := memory.NewUserDatabase(database.SystemUser)
	token := memory.NewTokenDatabase()
	cluster := memory.NewClusterDatabase()
	relay := memory.NewRelayLocator()
	auth.InitInterceptor(conf, u, token)

	testUser := &database.User{
		Id:    "test@example.com",
		Type:  database.UserTypeNormal,
		Roles: []string{"test-admin"},
	}
	testUser.Setup()
	if err := u.Set(nil, testUser); err != nil {
		t.Fatal(err)
	}
	code, err := token.NewCode(nil, testUser.Id, "", "")
	if err != nil {
		t.Fatal(err)
	}
	userToken, err := token.IssueToken(nil, code.Code, "")
	if err != nil {
		t.Fatal(err)
	}

	_ = cluster.Join(nil)
	_ = relay.Set(context.Background(), &database.Relay{Name: "test", Addr: "127.0.0.1:10000"})

	s := NewServer(
		conf,
		u,
		token,
		cluster,
		relay,
		memory.NewCA(conf.General.CertificateAuthority),
		func() bool { return true },
	)
	go func() {
		if err := s.Start(); err != nil {
			t.Fatal(err)
		}
	}()
	if err := netutil.WaitListen(fmt.Sprintf(":%d", port), 5*time.Second); err != nil {
		t.Fatal(err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	transCreds := credentials.NewTLS(&tls.Config{
		ServerName: conf.General.ServerNameHost,
		RootCAs:    caPool,
	})
	conn, err := grpc.Dial(fmt.Sprintf(":%d", port), grpc.WithTransportCredentials(transCreds))
	if err != nil {
		t.Fatal(err)
	}

	md := metadata.New(map[string]string{rpc.InternalTokenMetadataKey: "internal-token"})
	systemUserCtx := metadata.NewOutgoingContext(context.Background(), md)

	md = metadata.New(map[string]string{rpc.TokenMetadataKey: userToken.Token})
	testUserCtx := metadata.NewOutgoingContext(context.Background(), md)

	t.Run("Admin", func(t *testing.T) {
		t.Parallel()

		adminClient := rpc.NewAdminClient(conn)
		res, err := adminClient.Ping(context.Background(), &rpc.RequestPing{})
		if err != nil {
			t.Fatal(err)
		}
		if res == nil {
			t.Error("Expect return a value")
		}

		t.Run("Get Config", func(t *testing.T) {
			backendListRes, err := adminClient.BackendList(systemUserCtx, &rpc.RequestBackendList{})
			if err != nil {
				t.Fatal(err)
			}
			if len(backendListRes.GetItems()) != 1 {
				t.Errorf("BackendList should return an array that have 1 element: %d", len(backendListRes.GetItems()))
			}

			roleListRes, err := adminClient.RoleList(systemUserCtx, &rpc.RequestRoleList{})
			if err != nil {
				t.Fatal(err)
			}
			if len(roleListRes.GetItems()) != 3 {
				t.Errorf("RoleList should return an array that have 3 elements: %d", len(roleListRes.GetItems()))
			}
		})

		t.Run("Management User", func(t *testing.T) {
			t.Parallel()

			addRes, err := adminClient.UserAdd(systemUserCtx, &rpc.RequestUserAdd{
				Id:   testUser.Id,
				Type: rpc.UserType_NORMAL,
				Role: "test-admin2",
			})
			if err != nil {
				t.Fatal(err)
			}
			if !addRes.GetOk() {
				t.Error("Expect return ok")
			}

			getRes, err := adminClient.UserGet(systemUserCtx, &rpc.RequestUserGet{Id: testUser.Id, WithTokens: true})
			if err != nil {
				t.Fatal(err)
			}
			if getRes.GetUser().GetId() != "test@example.com" {
				t.Errorf("Unexpected Id: %s", getRes.GetUser().GetId())
			}
			if getRes.GetUser().GetRoles()[0] != "test-admin" || getRes.GetUser().GetRoles()[1] != "test-admin2" {
				t.Errorf("Unexpected role: %v", getRes.GetUser().GetRoles())
			}
			if getRes.GetUser().GetType() != rpc.UserType_NORMAL {
				t.Errorf("Unexpected user type: %v", getRes.GetUser().GetType())
			}

			becomeRes, err := adminClient.BecomeMaintainer(systemUserCtx, &rpc.RequestBecomeMaintainer{Id: testUser.Id, Role: "test-admin"})
			if err != nil {
				t.Fatal(err)
			}
			if !becomeRes.GetOk() {
				t.Error("Expect return ok")
			}

			getRes, err = adminClient.UserGet(systemUserCtx, &rpc.RequestUserGet{Id: "test@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			if len(getRes.GetUser().GetMaintainRoles()) != 1 {
				t.Error("test user should have a privilege to maintain 1 role")
			}

			userListRes, err := adminClient.UserList(systemUserCtx, &rpc.RequestUserList{})
			if err != nil {
				t.Fatal(err)
			}
			if len(userListRes.GetItems()) != 2 {
				t.Errorf("Expect 2 users: %d users", len(userListRes.GetItems()))
			}
			userListRes, err = adminClient.UserList(systemUserCtx, &rpc.RequestUserList{Role: "test-admin"})
			if err != nil {
				t.Fatal(err)
			}
			if len(userListRes.GetItems()) != 1 {
				t.Errorf("Expect 1 user: %d users", len(userListRes.GetItems()))
			}
			userListRes, err = adminClient.UserList(systemUserCtx, &rpc.RequestUserList{ServiceAccount: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(userListRes.GetItems()) != 1 {
				t.Errorf("Expect 1 user: %d users", len(userListRes.GetItems()))
			}

			toggleRes, err := adminClient.ToggleAdmin(systemUserCtx, &rpc.RequestToggleAdmin{Id: testUser.Id})
			if err != nil {
				t.Fatal(err)
			}
			if !toggleRes.GetOk() {
				t.Error("Expect return ok")
			}
			userListRes, err = adminClient.UserList(testUserCtx, &rpc.RequestUserList{})
			if err != nil {
				t.Fatal(err)
			}
			if len(userListRes.GetItems()) != 2 {
				t.Errorf("Expect 2 users: %d users", len(userListRes.GetItems()))
			}

			tokenRes, err := adminClient.TokenNew(systemUserCtx, &rpc.RequestTokenNew{Name: "test", UserId: testUser.Id})
			if err != nil {
				t.Fatal(err)
			}
			if tokenRes.GetItem().GetValue() == "" {
				t.Error("Expect return a value")
			}
			getRes, err = adminClient.UserGet(systemUserCtx, &rpc.RequestUserGet{Id: testUser.Id, WithTokens: true})
			if err != nil {
				t.Fatal(err)
			}
			if len(getRes.GetUser().GetTokens()) != 1 {
				t.Errorf("Expect 1 token: %d tokens", len(getRes.GetUser().GetTokens()))
			}
			if getRes.GetUser().GetTokens()[0].GetName() != "test" {
				t.Errorf("Unexpected name: %s", getRes.GetUser().GetTokens()[0].GetName())
			}
			if getRes.GetUser().GetTokens()[0].GetIssuer() != database.SystemUser.Id {
				t.Errorf("Unexpected issuer: %s", getRes.GetUser().GetTokens()[0].GetIssuer())
			}
		})
	})

	t.Run("Authority", func(t *testing.T) {
		t.Parallel()

		authorityClient := rpc.NewAuthorityClient(conn)

		pubKeyRes, err := authorityClient.GetPublicKey(systemUserCtx, &rpc.RequestGetPublicKey{})
		if err != nil {
			t.Fatal(err)
		}
		if len(pubKeyRes.PublicKey) == 0 {
			t.Error("Expect return a public key")
		}
		b, rest := pem.Decode(pubKeyRes.PublicKey)
		if len(rest) != 0 {
			t.Fatal("responsed value decoded as a pem block but have rest bytes")
		}
		if b.Type != "PUBLIC KEY" {
			t.Errorf("Expect Public Key: %s", b.Type)
		}
		pub, err := x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		switch pub.(type) {
		case *ecdsa.PublicKey:
		default:
			t.Fatal("Unexpected public key type")
		}

		signRes, err := authorityClient.SignRequest(systemUserCtx, &rpc.RequestSignRequest{UserId: testUser.Id})
		if err != nil {
			t.Fatal(err)
		}
		if len(signRes.Token) == 0 {
			t.Fatal("Expect return token")
		}
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
		if err != nil {
			t.Fatal(err)
		}
		if !newRes.GetOk() {
			t.Fatal("Expect return ok")
		}

		csr, _, err := cert.CreateCertificateRequest(pkix.Name{CommonName: "csr@example.com"}, []string{})
		if err != nil {
			t.Fatal(err)
		}
		newRes, err = caClient.NewClientCert(systemUserCtx, &rpc.RequestNewClientCert{
			Csr:        string(csr),
			CommonName: "csr@example.com",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !newRes.GetOk() {
			t.Fatal("Expect return ok")
		}

		newRes, err = caClient.NewClientCert(systemUserCtx, &rpc.RequestNewClientCert{
			Agent:      true,
			CommonName: "test",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !newRes.GetOk() {
			t.Fatal("Expect return ok")
		}

		signedListRes, err := caClient.GetSignedList(systemUserCtx, &rpc.RequestGetSignedList{})
		if err != nil {
			t.Fatal(err)
		}
		if len(signedListRes.Items) != 3 {
			t.Errorf("Expect return 3 signed certificates: %d signed certificates", len(signedListRes.Items))
		}

		revokedCert, err := caClient.Get(systemUserCtx, &rpc.CARequestGet{SerialNumber: signedListRes.Items[0].SerialNumber})
		if err != nil {
			t.Fatal(err)
		}
		if revokedCert.Item == nil {
			t.Error("Get should return certificate item")
		}

		revokeRes, err := caClient.Revoke(systemUserCtx, &rpc.CARequestRevoke{SerialNumber: revokedCert.Item.SerialNumber})
		if err != nil {
			t.Fatal(err)
		}
		if !revokeRes.GetOk() {
			t.Error("Expect return ok")
		}
		revokedListRes, err := caClient.GetRevokedList(systemUserCtx, &rpc.RequestGetRevokedList{})
		if err != nil {
			t.Fatal(err)
		}
		if len(revokedListRes.GetItems()) != 1 {
			t.Errorf("Expect 1 revoked certificate: %d revoked certificates", len(revokedListRes.GetItems()))
		}

		csr, _, err = cert.CreateCertificateRequest(pkix.Name{CommonName: "test.example.com"}, []string{"test.example.com"})
		if err != nil {
			t.Fatal(err)
		}
		newServerCertRes, err := caClient.NewServerCert(systemUserCtx, &rpc.RequestNewServerCert{SigningRequest: csr})
		if err != nil {
			t.Fatal(err)
		}
		if len(newServerCertRes.Certificate) == 0 {
			t.Error("NewServerCert should return a certificate")
		}
	})

	t.Run("Cluster", func(t *testing.T) {
		t.Parallel()

		clusterClient := rpc.NewClusterClient(conn)

		memberListRes, err := clusterClient.MemberList(systemUserCtx, &rpc.RequestMemberList{})
		if err != nil {
			t.Fatal(err)
		}
		if len(memberListRes.GetItems()) != 1 {
			t.Errorf("Expect return 1 member: %d members", len(memberListRes.GetItems()))
		}
		if memberListRes.GetItems()[0].GetId() != hostname {
			t.Errorf("Expect %v", memberListRes.GetItems()[0].GetId())
		}

		memberStatRes, err := clusterClient.MemberStat(systemUserCtx, &rpc.RequestMemberStat{})
		if err != nil {
			t.Fatal(err)
		}
		if memberStatRes.GetId() != cluster.Id() {
			t.Fatal("Unexpected id")
		}
		if memberStatRes.GetUserCount() != 2 {
			t.Errorf("Expect 2 users: %d users", memberStatRes.GetUserCount())
		}
		if memberStatRes.GetTokenCount() != 1 {
			t.Errorf("Expect 1 token: %d tokens", memberStatRes.GetTokenCount())
		}
		if len(memberStatRes.GetListenedRelayAddrs()) != 1 {
			t.Errorf("Expect 1 relay addr: %d addrs", len(memberStatRes.GetListenedRelayAddrs()))
		}

		agentListRes, err := clusterClient.AgentList(systemUserCtx, &rpc.RequestAgentList{})
		if err != nil {
			t.Fatal(err)
		}
		if len(agentListRes.GetItems()) != 1 {
			t.Fatalf("Expect 1 agent: %d agents", len(agentListRes.GetItems()))
		}
		if agentListRes.GetItems()[0].GetName() != "test" {
			t.Errorf("Expect agent name is test: %s", agentListRes.GetItems()[0].GetName())
		}

		defragmentRes, err := clusterClient.DefragmentDatastore(systemUserCtx, &rpc.RequestDefragmentDatastore{})
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range defragmentRes.GetOk() {
			if !v {
				t.Error("Expect return ok")
			}
		}
	})

	t.Run("Health", func(t *testing.T) {
		t.Parallel()

		healthClient := healthpb.NewHealthClient(conn)

		checkRes, err := healthClient.Check(systemUserCtx, &healthpb.HealthCheckRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if checkRes.Status != healthpb.HealthCheckResponse_SERVING {
			t.Errorf("Expect Serving: %v", checkRes.Status)
		}
	})
}
