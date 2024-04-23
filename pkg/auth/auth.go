package auth

import (
	"context"
	"net/http"

	"go.f110.dev/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.f110.dev/heimdallr/pkg/auth/authn"
	"go.f110.dev/heimdallr/pkg/auth/authz"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/rpc"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
	"go.f110.dev/heimdallr/pkg/session"
)

var (
	ErrHostnameNotFound   = xerrors.New("auth: hostname not found")
	ErrSessionNotFound    = xerrors.New("auth: session not found")
	ErrInvalidCertificate = xerrors.New("auth: invalid certificate")
	ErrInvalidToken       = xerrors.New("auth: invalid token")
	ErrUserNotFound       = xerrors.New("auth: user not found")
	ErrNotAllowed         = xerrors.New("auth: not allowed")
)

var (
	unauthorizedError = status.New(codes.Unauthenticated, "not provided valid token")
)
var errorMap = map[error]error{
	authn.ErrSessionNotFound:    ErrSessionNotFound,
	authn.ErrUserNotFound:       ErrUserNotFound,
	authn.ErrNotAllowed:         ErrNotAllowed,
	authn.ErrInvalidCertificate: ErrInvalidCertificate,
	authn.ErrHostnameNotFound:   ErrHostnameNotFound,
	authn.ErrInvalidToken:       ErrInvalidToken,
	authz.ErrSessionNotFound:    ErrSessionNotFound,
	authz.ErrNotAllowed:         ErrNotAllowed,
	authz.ErrHostnameNotFound:   ErrHostnameNotFound,
}

type revokedCertClient interface {
	Get() []*rpcclient.RevokedCert
}

// Init is initializing authenticator. You must call first before calling Authenticate.
func Init(conf *configv2.Config, sessionStore session.Store, userDatabase database.UserDatabase, tokenDatabase database.TokenDatabase, revokedCert revokedCertClient) {
	authn.Init(conf, sessionStore, userDatabase, tokenDatabase, revokedCert)
	authz.Init(conf)

	v, err := unauthorizedError.WithDetails(&rpc.ErrorUnauthorized{
		Endpoint: conf.AccessProxy.TokenEndpoint,
	})
	if err != nil {
		panic(err)
	}
	unauthorizedError = v
}

func Authenticate(ctx context.Context, req *http.Request) (*database.User, *session.Session, error) {
	user, sess, err := authn.DefaultAuthentication.Authenticate(ctx, req)
	if err != nil {
		if v, ok := errorMap[err]; ok {
			return nil, nil, v
		} else {
			return nil, nil, err
		}
	}

	err = authz.DefaultAuthorization.Authorization(ctx, req, user, sess)
	if err != nil {
		if v, ok := errorMap[err]; ok {
			return user, sess, v
		} else {
			return user, sess, err
		}
	}

	return user, sess, nil
}

func AuthenticateSocket(ctx context.Context, token, host string) (*configv2.Backend, *database.User, error) {
	backend, user, err := authn.DefaultAuthentication.AuthenticateSocket(ctx, token, host)
	if err != nil {
		if v, ok := errorMap[err]; ok {
			return nil, nil, v
		} else {
			return nil, nil, err
		}
	}

	err = authz.DefaultAuthorization.AuthorizationSocket(ctx, backend, user)
	if err != nil {
		if v, ok := errorMap[err]; ok {
			return nil, nil, v
		} else {
			return nil, nil, err
		}
	}

	return backend, user, nil
}

func UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if info == nil {
		return nil, unauthorizedError.Err()
	}

	// Skip authentication
	switch info.FullMethod {
	case "/grpc.health.v1.Health/Check", "/proxy.rpc.Admin/Ping":
		return handler(ctx, req)
	}

	user, err := authn.DefaultAuthentication.UnaryCall(ctx)
	if err != nil {
		return nil, unauthorizedError.Err()
	}

	err = authz.DefaultAuthorization.UnaryCall(info, user)
	if err != nil {
		return nil, unauthorizedError.Err()
	}

	ctx = context.WithValue(ctx, "user", user)
	return handler(ctx, req)
}

func StreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if info == nil {
		return unauthorizedError.Err()
	}

	// Skip authentication for health check endpoint
	if info.FullMethod == "/grpc.health.v1.Health/Watch" {
		return handler(srv, ss)
	}

	user, err := authn.DefaultAuthentication.StreamCall(ss)
	if err != nil {
		return unauthorizedError.Err()
	}
	_ = user

	return handler(srv, ss)
}
