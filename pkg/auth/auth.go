package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc"
	"github.com/f110/lagrangian-proxy/pkg/session"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var defaultAuthenticator = &authenticator{}

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

type authenticator struct {
	Config        *config.General
	sessionStore  session.Store
	userDatabase  database.UserDatabase
	ca            database.CertificateAuthority
	tokenDatabase database.TokenDatabase
	publicKey     ecdsa.PublicKey
}

// Init is initializing authenticator. You must call first before calling Authenticate.
func Init(conf *config.Config, sessionStore session.Store, userDatabase database.UserDatabase, ca database.CertificateAuthority, tokenDatabase database.TokenDatabase) {
	defaultAuthenticator.Config = conf.General
	defaultAuthenticator.sessionStore = sessionStore
	defaultAuthenticator.userDatabase = userDatabase
	defaultAuthenticator.ca = ca
	defaultAuthenticator.tokenDatabase = tokenDatabase
	defaultAuthenticator.publicKey = conf.FrontendProxy.SigningPublicKey

	v, err := unauthorizedError.WithDetails(&rpc.ErrorUnauthorized{
		Endpoint: conf.General.TokenEndpoint,
	})
	if err != nil {
		panic(err)
	}
	unauthorizedError = v
}

func Authenticate(req *http.Request) (*database.User, error) {
	return defaultAuthenticator.Authenticate(req)
}

func AuthenticateForSocket(ctx context.Context, token, host string) (*database.User, error) {
	return defaultAuthenticator.AuthenticateForSocket(ctx, token, host)
}

func UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	return defaultAuthenticator.UnaryInterceptor(ctx, req, info, handler)
}

func StreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return defaultAuthenticator.StreamInterceptor(srv, ss, info, handler)
}

func (a *authenticator) Authenticate(req *http.Request) (*database.User, error) {
	backend, ok := a.Config.GetBackendByHost(req.Host)
	if !ok {
		return nil, ErrHostnameNotFound
	}

	user, err := a.findUser(req)
	if backend.AllowAsRootUser && err == ErrUserNotFound {
		u, err := a.findRootUser(req)
		if err != nil {
			return nil, err
		}
		return u, nil
	} else if err != nil {
		return nil, err
	}

	matched := backend.MatchList(req)
	if len(matched) == 0 {
		return nil, ErrNotAllowed
	}
	for _, r := range user.Roles {
		role, err := a.Config.GetRole(r)
		if err == config.ErrRoleNotFound {
			continue
		}
		if err != nil {
			continue
		}
		for _, b := range role.Bindings {
			if b.Backend == backend.Name {
				if _, ok := matched[b.Permission]; ok {
					return user, nil
				}
			}
		}
	}

	return nil, ErrNotAllowed
}

func (a *authenticator) AuthenticateForSocket(ctx context.Context, token, host string) (*database.User, error) {
	if token == "" {
		return nil, ErrInvalidToken
	}
	if host == "" {
		return nil, ErrHostnameNotFound
	}
	backend, ok := a.Config.GetBackendByHostname(host)
	if !ok {
		return nil, ErrHostnameNotFound
	}

	t, err := a.tokenDatabase.FindToken(ctx, token)
	if err != nil {
		return nil, ErrInvalidToken
	}
	user, err := a.userDatabase.Get(t.UserId)
	if err != nil {
		return nil, ErrUserNotFound
	}

	for _, r := range user.Roles {
		role, err := a.Config.GetRole(r)
		if err == config.ErrRoleNotFound {
			continue
		}
		if err != nil {
			continue
		}
		for _, b := range role.Bindings {
			if b.Backend == backend.Name {
				return user, nil
			}
		}
	}

	return nil, ErrNotAllowed
}

func (a *authenticator) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, unauthorizedError.Err()
	}

	user, err := a.authenticateByMetadata(ctx, md)
	if err != nil {
		return nil, unauthorizedError.Err()
	}
	ctx = context.WithValue(ctx, "user", user)

	ok = false
	for _, v := range user.Roles {
		role, err := a.Config.GetRole(v)
		if err != nil {
			continue
		}
		if v := role.RPCMethodMatcher.Match(info.FullMethod); v {
			ok = true
			break
		}
	}
	if !ok {
		return nil, unauthorizedError.Err()
	}

	return handler(ctx, req)
}

func (a *authenticator) StreamInterceptor(srv interface{}, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	md, ok := metadata.FromIncomingContext(ss.Context())
	if !ok {
		return unauthorizedError.Err()
	}

	_, err := a.authenticateByMetadata(ss.Context(), md)
	if err != nil {
		return unauthorizedError.Err()
	}

	return handler(srv, ss)
}

func (a *authenticator) authenticateByMetadata(ctx context.Context, md metadata.MD) (*database.User, error) {
	if len(md.Get(rpc.TokenMetadataKey)) == 0 && len(md.Get(rpc.JwtTokenMetadataKey)) == 0 {
		return nil, ErrSessionNotFound
	}

	userId := ""
	if len(md.Get(rpc.TokenMetadataKey)) > 0 {
		tokenString := md.Get(rpc.TokenMetadataKey)[0]

		token, err := a.tokenDatabase.FindToken(ctx, tokenString)
		if err != nil {
			logger.Log.Info("Could not find token", zap.Error(err))
			return nil, ErrInvalidToken
		}
		userId = token.UserId
	} else if len(md.Get(rpc.JwtTokenMetadataKey)) > 0 {
		j := md.Get(rpc.JwtTokenMetadataKey)[0]
		claims := &jwt.StandardClaims{}
		_, err := jwt.ParseWithClaims(j, claims, func(token *jwt.Token) (i interface{}, e error) {
			if token.Method != jwt.SigningMethodES256 {
				return nil, xerrors.New("auth: invalid signing method")
			}
			return &a.publicKey, nil
		})
		if err != nil {
			return nil, ErrInvalidToken
		}
		if err := claims.Valid(); err != nil {
			return nil, ErrInvalidToken
		}
		userId = claims.Id
	}

	var rootUser *database.User
	for _, v := range a.Config.RootUsers {
		if v == userId {
			rootUser = &database.User{Id: userId, Admin: true}
		}
	}

	user, err := a.userDatabase.Get(userId)
	if err != nil && rootUser == nil {
		logger.Log.Info("Could not find user", zap.Error(err))
		return nil, ErrUserNotFound
	}
	if user == nil && rootUser != nil {
		return rootUser, nil
	}

	return user, nil
}

func (a *authenticator) findUser(req *http.Request) (*database.User, error) {
	if len(req.TLS.PeerCertificates) > 0 {
		// Client Certificate Authorization
		cert := req.TLS.PeerCertificates[0]
		if time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
			return nil, ErrInvalidCertificate
		}
		_, err := cert.Verify(x509.VerifyOptions{
			Roots:     a.Config.CertificateAuthority.CertPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			return nil, ErrInvalidCertificate
		}

		u, err := a.userDatabase.Get(cert.Subject.CommonName)
		if err != nil {
			return nil, ErrUserNotFound
		}

		revoked := a.ca.GetRevokedCertificates()
		for _, r := range revoked {
			if r.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return nil, ErrInvalidCertificate
			}
		}

		return u, nil
	}

	if v := req.Header.Get("Authorization"); v == "LP-TOKEN" {
		token := req.Header.Get("X-LP-Token")
		if token == "" {
			return nil, ErrUserNotFound
		}
		at, err := a.userDatabase.GetAccessToken(token)
		if err != nil {
			return nil, ErrUserNotFound
		}
		user, err := a.userDatabase.Get(at.UserId)
		if err != nil {
			return nil, ErrUserNotFound
		}
		return user, nil
	}

	s, err := a.sessionStore.GetSession(req)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if s.Id == "" {
		return nil, ErrSessionNotFound
	}
	u, err := a.userDatabase.Get(s.Id)
	if err != nil {
		return nil, ErrUserNotFound
	}

	return u, nil
}

func (a *authenticator) findRootUser(req *http.Request) (*database.User, error) {
	s, err := a.sessionStore.GetSession(req)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if s.Id == "" {
		return nil, ErrSessionNotFound
	}

	asRootUser := false
	for _, v := range a.Config.RootUsers {
		if v == s.Id {
			asRootUser = true
			break
		}
	}
	if !asRootUser {
		return nil, ErrUserNotFound
	}

	return &database.User{
		Id:       s.Id,
		RootUser: true,
	}, nil
}

func (a *authenticator) findUserByToken(token string) (*database.User, error) {
	return nil, ErrUserNotFound
}
