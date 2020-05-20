package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/f110/lagrangian-proxy/pkg/cert"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/database/memory"
	"github.com/f110/lagrangian-proxy/pkg/rpc"
	"github.com/f110/lagrangian-proxy/pkg/rpc/rpcclient"
	"github.com/f110/lagrangian-proxy/pkg/session"
)

func TestInit(t *testing.T) {
	Init(
		&config.Config{General: &config.General{}},
		session.NewSecureCookieStore([]byte(""), []byte(""), ""),
		memory.NewUserDatabase(),
		memory.NewTokenDatabase(),
		&testRevokedCertClient{},
	)
}

func TestInitInterceptor(t *testing.T) {
	InitInterceptor(
		&config.Config{General: &config.General{}},
		memory.NewUserDatabase(),
		memory.NewTokenDatabase(),
	)
}

func TestAuthenticator_Authenticate(t *testing.T) {
	s := session.NewSecureCookieStore([]byte("test"), []byte("testtesttesttesttesttesttesttest"), "example.com")
	u := memory.NewUserDatabase()
	rc := &testRevokedCertClient{}
	caCert, caPrivateKey, err := cert.CreateCertificateAuthority("for test", "test", "", "jp")
	if err != nil {
		t.Fatal(err)
	}
	cp := x509.NewCertPool()
	cp.AddCert(caCert)
	a := &authenticator{
		Config: &config.General{
			ServerNameHost: "proxy.example.com",
			RootUsers:      []string{"root@example.com"},
			Backends: []*config.Backend{
				{
					Name: "test",
					Permissions: []*config.Permission{
						{Name: "ok", Locations: []config.Location{{Get: "/ok"}}},
						{Name: "ok_but_nobind", Locations: []config.Location{{Get: "/no_bind"}}},
					},
				},
				{
					Name:            "root",
					AllowAsRootUser: true,
					Permissions: []*config.Permission{
						{Name: "ok", Locations: []config.Location{{Get: "/ok"}}},
					},
				},
				{
					Name:         "public",
					DisableAuthn: true,
				},
				{
					Name:         "public-path",
					DisableAuthn: true,
					Permissions: []*config.Permission{
						{Name: "ok", Locations: []config.Location{{Get: "/ok"}}},
					},
				},
			},
			Roles: []*config.Role{
				{Name: "test", Bindings: []*config.Binding{
					{Backend: "test", Permission: "ok"},
				}},
			},
			CertificateAuthority: &config.CertificateAuthority{
				Certificate: caCert,
				PrivateKey:  caPrivateKey,
				CertPool:    cp,
			},
		},
		sessionStore: s,
		userDatabase: u,
		revokedCert:  rc,
	}
	defaultAuthenticator = a
	err = a.Config.Load(a.Config.Backends, a.Config.Roles, []*config.RpcPermission{})
	if err != nil {
		t.Fatal(err)
	}
	_ = u.Set(nil, &database.User{Id: "foobar@example.com", Roles: []string{"test", "unknown"}})

	t.Run("DisableAuthentication", func(t *testing.T) {
		t.Parallel()

		t.Run("any path", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://public.proxy.example.com/ok", nil)
			_, err := Authenticate(req)
			if err != nil {
				t.Fatal(err)
			}
		})

		t.Run("with restricted path", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://public-path.proxy.example.com/ok", nil)
			_, err := Authenticate(req)
			if err != nil {
				t.Fatal(err)
			}
		})

		t.Run("with not allowed path", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://public-path.proxy.example.com/disallow", nil)
			_, err := Authenticate(req)
			if err != ErrNotAllowed {
				t.Fatalf("expected ErrNotAllowed: %v", err)
			}
		})
	})

	t.Run("Cookie", func(t *testing.T) {
		t.Parallel()

		t.Run("normal", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)
			c, err := s.Cookie(session.New("foobar@example.com"))
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(c)

			user, err := Authenticate(req)
			if err != nil {
				t.Fatal(err)
			}
			if user.Id != "foobar@example.com" {
				t.Errorf("expect foobar@example.com: %s", user.Id)
			}

			user, err = a.Authenticate(req)
			if err != nil {
				t.Fatal(err)
			}
			if user.Id != "foobar@example.com" {
				t.Errorf("expect foobar@example.com: %s", user.Id)
			}
		})

		t.Run("normal with root user", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://root.proxy.example.com/ok", nil)
			c, err := s.Cookie(session.New("root@example.com"))
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(c)
			user, err := a.Authenticate(req)
			if err != nil {
				t.Fatal(err)
			}
			if user.Id != "root@example.com" {
				t.Errorf("expect foobar@example.com: %s", user.Id)
			}
			if !user.RootUser {
				t.Error("expect root@example.com is root")
			}
		})

		t.Run("not have cookie", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)

			_, err := a.Authenticate(req)
			if err != ErrSessionNotFound {
				t.Errorf("expect session not found: %v", err)
			}
		})

		t.Run("user not found", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)
			c, err := s.Cookie(session.New("foo@example.com"))
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(c)
			_, err = a.Authenticate(req)
			if err != ErrUserNotFound {
				t.Errorf("expect user not found: %v", err)
			}
		})

		t.Run("unknown host", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://unknownhost.example.com/ok", nil)

			_, err := a.Authenticate(req)
			if err != ErrHostnameNotFound {
				t.Errorf("expect hostname not found: %v", err)
			}
		})

		t.Run("not allowed path", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/no_good", nil)
			c, err := s.Cookie(session.New("foobar@example.com"))
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(c)
			_, err = a.Authenticate(req)
			if err != ErrNotAllowed {
				t.Errorf("expect not allowed: %v", err)
			}
		})

		t.Run("role not have clearance", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/no_bind", nil)
			c, err := s.Cookie(session.New("foobar@example.com"))
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(c)
			_, err = a.Authenticate(req)
			if err != ErrNotAllowed {
				t.Errorf("expect not allowed: %v", err)
			}
		})
	})

	t.Run("client certificate auth", func(t *testing.T) {
		t.Parallel()

		t.Run("normal", func(t *testing.T) {
			t.Parallel()

			subject := pkix.Name{CommonName: "foobar@example.com"}
			pemEncodedCSRBytes, _, err := cert.CreateCertificateRequest(subject, []string{})
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(pemEncodedCSRBytes)
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			clientCert, err := cert.SigningCertificateRequest(csr, a.Config.CertificateAuthority)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)
			req.TLS = &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{clientCert},
			}
			user, err := a.Authenticate(req)
			if err != nil {
				t.Fatal(err)
			}
			if user.Id != "foobar@example.com" {
				t.Errorf("expect foobar@example.com: %s", user.Id)
			}
		})

		t.Run("normal via client certificate auth", func(t *testing.T) {
			t.Parallel()

			subject := pkix.Name{CommonName: "foobar@example.com"}
			pemEncodedCSRBytes, _, err := cert.CreateCertificateRequest(subject, []string{})
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(pemEncodedCSRBytes)
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			clientCert, err := cert.SigningCertificateRequest(csr, a.Config.CertificateAuthority)
			if err != nil {
				t.Fatal(err)
			}
			rc.revokedCert = append(rc.revokedCert, &rpcclient.RevokedCert{SerialNumber: clientCert.SerialNumber})
			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)
			req.TLS = &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{clientCert},
			}
			_, err = a.Authenticate(req)
			if err == nil {
				t.Fatal("expected to occurred error but not")
			}
			if err != ErrInvalidCertificate {
				t.Fatalf("expected ErrInvalidCertificate: %v", err)
			}
		})
	})

	t.Run("Authorization header", func(t *testing.T) {
		t.Parallel()

		t.Run("normal", func(t *testing.T) {
			t.Parallel()

			err := u.SetAccessToken(context.Background(), &database.AccessToken{Value: t.Name(), UserId: "foobar@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)
			req.Header.Set("Authorization", "LP-TOKEN")
			req.Header.Set("X-LP-TOKEN", t.Name())
			user, err := a.Authenticate(req)
			if err != nil {
				t.Fatal(err)
			}
			if user.Id != "foobar@example.com" {
				t.Errorf("expect foobar@example.com: %s", user.Id)
			}
		})

		t.Run("header not found", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)
			req.Header.Set("Authorization", "LP-TOKEN")
			_, err = a.Authenticate(req)
			if err == nil {
				t.Fatal("expected to occurred error but not")
			}
			if err != ErrUserNotFound {
				t.Fatalf("expected ErrUserNotFound: %v", err)
			}
		})

		t.Run("invalid token", func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)
			req.Header.Set("Authorization", "LP-TOKEN")
			req.Header.Set("X-LP-Token", "unknown-token")
			_, err = a.Authenticate(req)
			if err == nil {
				t.Fatal("expected to occurred error but not")
			}
			if err != ErrUserNotFound {
				t.Fatalf("expected ErrUserNotFound: %v", err)
			}
		})

		t.Run("user not found", func(t *testing.T) {
			t.Parallel()

			err := u.SetAccessToken(context.Background(), &database.AccessToken{Value: "dummy-token", UserId: "piyo@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "http://test.proxy.example.com/ok", nil)
			req.Header.Set("Authorization", "LP-TOKEN")
			req.Header.Set("X-LP-TOKEN", "dummy-token")
			_, err = a.Authenticate(req)
			if err == nil {
				t.Fatal("expected to occurred error but not")
			}
			if err != ErrUserNotFound {
				t.Fatalf("expected ErrUserNotFound: %v", err)
			}
		})
	})
}

func TestAuthenticator_AuthenticateForSocket(t *testing.T) {
	s := session.NewSecureCookieStore([]byte("test"), []byte("testtesttesttesttesttesttesttest"), "example.com")
	u := memory.NewUserDatabase()
	token := memory.NewTokenDatabase()
	a := &authenticator{
		Config: &config.General{
			ServerNameHost: "proxy.example.com",
			Backends: []*config.Backend{
				{
					Name:   "test",
					Socket: true,
					Permissions: []*config.Permission{
						{Name: "ok", Locations: []config.Location{{Get: "/ok"}}},
						{Name: "ok_but_nobind", Locations: []config.Location{{Get: "/no_bind"}}},
					},
				},
			},
			Roles: []*config.Role{
				{
					Name: "test",
					Bindings: []*config.Binding{
						{Backend: "test"},
					},
				},
			},
		},
		sessionStore:  s,
		userDatabase:  u,
		tokenDatabase: token,
	}
	defaultAuthenticator = a
	err := a.Config.Load(a.Config.Backends, a.Config.Roles, []*config.RpcPermission{})
	if err != nil {
		t.Fatal(err)
	}
	_ = u.Set(nil, &database.User{Id: "foobar@example.com", Roles: []string{"test", "unknown"}})
	_ = u.Set(nil, &database.User{Id: "piyo@example.com", Roles: []string{}})

	t.Run("empty token", func(t *testing.T) {
		t.Parallel()

		_, err := a.AuthenticateForSocket(context.Background(), "", "")
		if err == nil {
			t.Fatal("expected to occurred error but not")
		}
		if err != ErrInvalidToken {
			t.Fatalf("expected ErrInvalidToken: %v", err)
		}
	})

	t.Run("empty host", func(t *testing.T) {
		t.Parallel()

		_, err := a.AuthenticateForSocket(context.Background(), "dummy", "")
		if err == nil {
			t.Fatal("expected to occurred error but not")
		}
		if err != ErrHostnameNotFound {
			t.Fatalf("expected ErrHostnameNotFound: %v", err)
		}
	})

	t.Run("unknown host", func(t *testing.T) {
		t.Parallel()

		_, err := a.AuthenticateForSocket(context.Background(), "dummy", "unknown")
		if err == nil {
			t.Fatal("expected to occurred error but not")
		}
		if err != ErrHostnameNotFound {
			t.Fatalf("expected ErrHostnameNotFound: %v", err)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		t.Parallel()

		_, err := a.AuthenticateForSocket(context.Background(), "dummy", "test.proxy.example.com")
		if err == nil {
			t.Fatal("expected to occurred error but not")
		}
		if err != ErrInvalidToken {
			t.Fatalf("expected ErrInvalidToken: %v", err)
		}
	})

	t.Run("unknown user", func(t *testing.T) {
		t.Parallel()

		newToken, err := token.IssueToken(context.Background(), "", "")
		if err != nil {
			t.Fatal(err)
		}
		_, err = a.AuthenticateForSocket(context.Background(), newToken.Token, "test.proxy.example.com")
		if err == nil {
			t.Fatal("expected to occurred error but not")
		}
		if err != ErrUserNotFound {
			t.Fatalf("expected ErrUserNotFound: %v", err)
		}
	})

	t.Run("user not allowed", func(t *testing.T) {
		t.Parallel()

		newCode, err := token.NewCode(context.Background(), "piyo@example.com", "", "")
		if err != nil {
			t.Fatal(err)
		}
		newToken, err := token.IssueToken(context.Background(), newCode.Code, "")
		if err != nil {
			t.Fatal(err)
		}
		_, err = a.AuthenticateForSocket(context.Background(), newToken.Token, "test.proxy.example.com")
		if err == nil {
			t.Fatal("expected to occurred error but not")
		}
		if err != ErrNotAllowed {
			t.Fatalf("expected ErrNotAllowed: %v", err)
		}
	})

	t.Run("allow", func(t *testing.T) {
		t.Parallel()

		newCode, err := token.NewCode(context.Background(), "foobar@example.com", "", "")
		if err != nil {
			t.Fatal(err)
		}
		newToken, err := token.IssueToken(context.Background(), newCode.Code, "")
		if err != nil {
			t.Fatal(err)
		}

		user, err := AuthenticateForSocket(context.Background(), newToken.Token, "test.proxy.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if user.Id != "foobar@example.com" {
			t.Fatalf("AuthenticateForSocket returns user but is not expected: %v", user.Id)
		}

		user, err = a.AuthenticateForSocket(context.Background(), newToken.Token, "test.proxy.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if user.Id != "foobar@example.com" {
			t.Fatalf("AuthenticateForSocket returns user but is not expected: %v", user.Id)
		}
	})
}

func TestAuthInterceptor_UnaryInterceptor(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	u := memory.NewUserDatabase(database.SystemUser)
	token := memory.NewTokenDatabase()
	a := &authInterceptor{
		Config: &config.General{
			ServerNameHost:    "proxy.example.com",
			SigningPrivateKey: privateKey,
			InternalToken:     "rpc-internal-token",
			Backends: []*config.Backend{
				{
					Name: "test",
					Permissions: []*config.Permission{
						{Name: "ok", Locations: []config.Location{{Get: "/ok"}}},
						{Name: "ok_but_nobind", Locations: []config.Location{{Get: "/no_bind"}}},
					},
				},
			},
			Roles: []*config.Role{
				{
					Name: "test",
					Bindings: []*config.Binding{
						{Rpc: "test"},
					},
				},
			},
			RpcPermissions: []*config.RpcPermission{
				{
					Name:  "test",
					Allow: []string{"test"},
				},
			},
		},
		userDatabase:  u,
		tokenDatabase: token,
		publicKey:     privateKey.PublicKey,
	}
	defaultAuthInterceptor = a
	err = a.Config.Load(a.Config.Backends, a.Config.Roles, a.Config.RpcPermissions)
	if err != nil {
		t.Fatal(err)
	}
	_ = u.Set(nil, &database.User{Id: "foobar@example.com", Roles: []string{"test"}})

	okHandler := func(_ context.Context, _ interface{}) (interface{}, error) {
		return true, nil
	}

	t.Run("with access token", func(t *testing.T) {
		t.Parallel()

		newCode, err := token.NewCode(context.Background(), "foobar@example.com", "", "")
		if err != nil {
			t.Fatal(err)
		}
		newToken, err := token.IssueToken(context.Background(), newCode.Code, "")
		if err != nil {
			t.Fatal(err)
		}

		md := metadata.New(map[string]string{rpc.TokenMetadataKey: newToken.Token})
		ctx := metadata.NewIncomingContext(context.Background(), md)

		v, err := UnaryInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test"}, okHandler)
		if err != nil {
			t.Fatal(err)
		}
		res, ok := v.(bool)
		if !ok {
			t.Fatal("response should be bool")
		}
		if !res {
			t.Fatal("unexpected response")
		}

		v, err = a.UnaryInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test"}, okHandler)
		if err != nil {
			t.Fatal(err)
		}
		res, ok = v.(bool)
		if !ok {
			t.Fatal("response should be bool")
		}
		if !res {
			t.Fatal("unexpected response")
		}
	})

	t.Run("with jwt", func(t *testing.T) {
		t.Parallel()

		claim := jwt.NewWithClaims(jwt.SigningMethodES256, &jwt.StandardClaims{
			Id:        "foobar@example.com",
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(10 * time.Second).Unix(),
		})
		jwtToken, err := claim.SignedString(a.Config.SigningPrivateKey)
		if err != nil {
			t.Fatal(err)
		}

		md := metadata.New(map[string]string{rpc.JwtTokenMetadataKey: jwtToken})
		ctx := metadata.NewIncomingContext(context.Background(), md)

		v, err := a.UnaryInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test"}, okHandler)
		if err != nil {
			t.Fatal(err)
		}
		res, ok := v.(bool)
		if !ok {
			t.Fatal("response should be bool")
		}
		if !res {
			t.Fatal("unexpected response")
		}
	})

	t.Run("with internal token", func(t *testing.T) {
		t.Parallel()

		md := metadata.New(map[string]string{rpc.InternalTokenMetadataKey: a.Config.InternalToken})
		ctx := metadata.NewIncomingContext(context.Background(), md)

		v, err := a.UnaryInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/proxy.rpc.certificateauthority.watchrevokedcert"}, okHandler)
		if err != nil {
			t.Fatal(err)
		}
		res, ok := v.(bool)
		if !ok {
			t.Fatal("response should be bool")
		}
		if !res {
			t.Fatal("unexpected response")
		}
	})

	t.Run("not provide metadata", func(t *testing.T) {
		t.Parallel()

		_, err := a.UnaryInterceptor(context.Background(), nil, nil, nil)
		if err == nil {
			t.Fatal("expect to occurred error but not")
		}
		if !errors.Is(err, unauthorizedError.Err()) {
			t.Fatalf("expect unauthorizedError: %v", err)
		}
	})

	t.Run("not provide token", func(t *testing.T) {
		t.Parallel()

		md := metadata.New(map[string]string{})
		ctx := metadata.NewIncomingContext(context.Background(), md)

		_, err := a.UnaryInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test"}, nil)
		if err == nil {
			t.Fatal("expect to occurred error but not")
		}
		if !errors.Is(err, unauthorizedError.Err()) {
			t.Fatalf("expect unauthorizedError: %v", err)
		}
	})

	t.Run("health check methods should not check a clearance", func(t *testing.T) {
		t.Parallel()

		methods := []string{"/grpc.health.v1.Health/Check", "/proxy.rpc.Admin/Ping"}

		md := metadata.New(map[string]string{})
		ctx := metadata.NewIncomingContext(context.Background(), md)
		// ctx := metadata.NewOutgoingContext(context.Background(), md)
		for _, m := range methods {
			v, err := a.UnaryInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: m}, func(_ context.Context, _ interface{}) (interface{}, error) {
				return true, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			res, ok := v.(bool)
			if !ok {
				t.Fatal("response should be bool")
			}
			if !res {
				t.Fatal("unexpected response")
			}
		}
	})
}

func TestAuthInterceptor_StreamInterceptor(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	u := memory.NewUserDatabase(database.SystemUser)
	token := memory.NewTokenDatabase()
	a := &authInterceptor{
		Config: &config.General{
			ServerNameHost:    "proxy.example.com",
			SigningPrivateKey: privateKey,
			InternalToken:     "rpc-internal-token",
			Backends: []*config.Backend{
				{
					Name: "test",
					Permissions: []*config.Permission{
						{Name: "ok", Locations: []config.Location{{Get: "/ok"}}},
						{Name: "ok_but_nobind", Locations: []config.Location{{Get: "/no_bind"}}},
					},
				},
			},
			Roles: []*config.Role{
				{
					Name: "test",
					Bindings: []*config.Binding{
						{Rpc: "test"},
					},
				},
			},
			RpcPermissions: []*config.RpcPermission{
				{
					Name:  "test",
					Allow: []string{"test"},
				},
			},
		},
		userDatabase:  u,
		tokenDatabase: token,
		publicKey:     privateKey.PublicKey,
	}
	defaultAuthInterceptor = a
	err = a.Config.Load(a.Config.Backends, a.Config.Roles, a.Config.RpcPermissions)
	if err != nil {
		t.Fatal(err)
	}

	okHandler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	t.Run("with internal token", func(t *testing.T) {
		t.Parallel()

		md := metadata.New(map[string]string{rpc.InternalTokenMetadataKey: a.Config.InternalToken})
		ctx := metadata.NewIncomingContext(context.Background(), md)

		err := StreamInterceptor(nil, &testServerStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: "/test"}, okHandler)
		if err != nil {
			t.Fatal(err)
		}

		err = a.StreamInterceptor(nil, &testServerStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: "/test"}, okHandler)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("not provide metadata", func(t *testing.T) {
		t.Parallel()

		err := a.StreamInterceptor(nil, &testServerStream{ctx: context.Background()}, nil, nil)
		if err == nil {
			t.Fatal("expect to occurred error but not")
		}
		if !errors.Is(err, unauthorizedError.Err()) {
			t.Fatalf("expect unauthorizedError: %v", err)
		}
	})

	t.Run("not provide token", func(t *testing.T) {
		t.Parallel()

		md := metadata.New(map[string]string{})
		ctx := metadata.NewIncomingContext(context.Background(), md)

		err := a.StreamInterceptor(nil, &testServerStream{ctx: ctx}, &grpc.StreamServerInfo{FullMethod: "/test"}, nil)
		if err == nil {
			t.Fatal("expect to occurred error but not")
		}
		if !errors.Is(err, unauthorizedError.Err()) {
			t.Fatalf("expect unauthorizedError: %v", err)
		}
	})
}
