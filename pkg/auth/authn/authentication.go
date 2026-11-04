package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"go.f110.dev/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/rpc"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
	"go.f110.dev/heimdallr/pkg/session"
)

var DefaultAuthentication = &authentication{}

var (
	ErrHostnameNotFound   = xerrors.New("authn: hostname not found")
	ErrSessionNotFound    = xerrors.New("authn: session not found")
	ErrInvalidCertificate = xerrors.New("authn: invalid certificate")
	ErrInvalidToken       = xerrors.New("authn: invalid token")
	ErrUserNotFound       = xerrors.New("authn: user not found")
	ErrNotAllowed         = xerrors.New("authn: not allowed")
)

// AuthMethod is the method used to authenticate the request.
// The value is used as the amr claim (RFC 8176) of the token for the backend.
type AuthMethod string

const (
	AuthMethodMTLS   AuthMethod = "mtls"
	AuthMethodToken  AuthMethod = "token"
	AuthMethodCookie AuthMethod = "cookie"
)

// Identity is the result of the authentication of the request.
type Identity struct {
	User *database.User
	// Session is nil if the request is authenticated by the client certificate without the cookie.
	Session *session.Session
	Method  AuthMethod
}

type authentication struct {
	Config *configv2.Config

	sessionStore  session.Store
	userDatabase  database.UserDatabase
	revokedCert   revokedCertClient
	tokenDatabase database.TokenDatabase
	publicKey     ecdsa.PublicKey
}

type revokedCertClient interface {
	Get() []*rpcclient.RevokedCert
}

func Init(conf *configv2.Config, sessionStore session.Store, userDatabase database.UserDatabase, tokenDatabase database.TokenDatabase, revokedCert revokedCertClient) {
	DefaultAuthentication.Config = conf
	DefaultAuthentication.sessionStore = sessionStore
	DefaultAuthentication.userDatabase = userDatabase
	DefaultAuthentication.revokedCert = revokedCert
	DefaultAuthentication.tokenDatabase = tokenDatabase
	if conf.AccessProxy.Credential != nil {
		DefaultAuthentication.publicKey = conf.AccessProxy.Credential.SigningPublicKey
	}
}

func (a *authentication) Authenticate(ctx context.Context, req *http.Request) (*Identity, error) {
	backend, ok := a.Config.AccessProxy.GetBackendByHost(req.Host)
	if !ok {
		return nil, ErrHostnameNotFound
	}
	if backend.DisableAuthn {
		if len(backend.Permissions) == 0 {
			return &Identity{User: &database.User{}}, nil
		}

		matched := backend.MatchList(req)
		if len(matched) == 0 {
			return nil, ErrNotAllowed
		}
		return &Identity{User: &database.User{}}, nil
	}

	identity, err := a.findUser(ctx, req)
	if errors.Is(err, ErrUserNotFound) {
		rootIdentity, rErr := a.findRootUser(req)
		if rErr != nil {
			return nil, err
		}
		return rootIdentity, nil
	} else if err != nil {
		return nil, err
	}

	return identity, nil
}

func (a *authentication) AuthenticateSocket(ctx context.Context, token, host string) (*configv2.Backend, *database.User, error) {
	if token == "" {
		return nil, nil, ErrInvalidToken
	}
	if host == "" {
		return nil, nil, ErrHostnameNotFound
	}
	backend, ok := a.Config.AccessProxy.GetBackendByHostname(host)
	if !ok {
		return nil, nil, ErrHostnameNotFound
	}

	user, _, err := a.findUserByToken(ctx, token)
	if err != nil {
		return nil, nil, err
	}

	return backend, user, nil
}

func (a *authentication) findUserByToken(ctx context.Context, token string) (*database.User, *database.Token, error) {
	t, err := a.tokenDatabase.FindToken(ctx, token)
	if err != nil {
		return nil, nil, ErrInvalidToken
	}
	user, err := a.userDatabase.Get(t.UserId)
	if err != nil {
		return nil, nil, ErrUserNotFound
	}

	return user, t, nil
}

func (a *authentication) UnaryCall(ctx context.Context) (*database.User, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		logger.Log.Info("Can't get metadata from incoming context")
		return nil, ErrSessionNotFound
	}

	user, err := a.authenticateByMetadata(ctx, md)
	if err != nil {
		logger.Log.Info("Failed request authentication", slog.Any("error", err))
		return nil, ErrSessionNotFound
	}

	return user, nil
}

func (a *authentication) StreamCall(ss grpc.ServerStream) (*database.User, error) {
	md, ok := metadata.FromIncomingContext(ss.Context())
	if !ok {
		return nil, ErrSessionNotFound
	}

	user, err := a.authenticateByMetadata(ss.Context(), md)
	if err != nil {
		logger.Log.Info("Failed request authentication", slog.Any("error", err))
		return nil, ErrSessionNotFound
	}

	return user, nil
}

func (a *authentication) findUser(ctx context.Context, req *http.Request) (*Identity, error) {
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		logger.Log.Debug("Client Certificate authorization", logger.WithRequestId(ctx))
		// Client Certificate Authorization
		cert := req.TLS.PeerCertificates[0]
		if time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
			logger.Log.Debug("Expired certificate", logger.WithRequestId(ctx))
			return nil, ErrInvalidCertificate
		}
		_, err := cert.Verify(x509.VerifyOptions{
			Roots:     a.Config.CertificateAuthority.CertPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			logger.Log.Debug("Failure verify certificate", slog.Any("error", err), logger.WithRequestId(ctx))
			return nil, ErrInvalidCertificate
		}

		u, err := a.userDatabase.Get(cert.Subject.CommonName)
		if err != nil {
			return nil, ErrUserNotFound
		}

		revoked := a.revokedCert.Get()
		for _, r := range revoked {
			if r.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				logger.Log.Debug("Revoked certificate", logger.WithRequestId(ctx))
				return nil, ErrInvalidCertificate
			}
		}

		// Session by cookie is an optional
		s, err := a.sessionStore.GetSession(req)
		if err != nil {
			return &Identity{User: u, Method: AuthMethodMTLS}, nil
		}

		return &Identity{User: u, Session: s, Method: AuthMethodMTLS}, nil
	}

	if token, ok, err := tokenFromAuthorizationHeader(req); ok {
		if err != nil {
			return nil, err
		}
		user, t, err := a.findUserByToken(ctx, token)
		if err != nil {
			return nil, err
		}

		return &Identity{
			User: user,
			Session: &session.Session{
				Id:       t.UserId,
				IssuedAt: t.IssuedAt,
			},
			Method: AuthMethodToken,
		}, nil
	}

	s, err := a.sessionStore.GetSession(req)
	if err != nil {
		logger.Log.Debug("Failed get session", slog.Any("error", err))
		return nil, ErrSessionNotFound
	}
	if s.Id == "" {
		logger.Log.Debug("Got session but id is empty")
		return nil, ErrSessionNotFound
	}
	u, err := a.userDatabase.Get(s.Id)
	if err != nil {
		return nil, ErrUserNotFound
	}

	return &Identity{User: u, Session: s, Method: AuthMethodCookie}, nil
}

func (a *authentication) findRootUser(req *http.Request) (*Identity, error) {
	s, err := a.sessionStore.GetSession(req)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if s.Id == "" {
		return nil, ErrSessionNotFound
	}

	asRootUser := slices.Contains(a.Config.AuthorizationEngine.RootUsers, s.Id)
	if !asRootUser {
		return nil, ErrUserNotFound
	}

	return &Identity{
		User: &database.User{
			Id:       s.Id,
			RootUser: true,
		},
		Session: s,
		Method:  AuthMethodCookie,
	}, nil
}

func (a *authentication) authenticateByMetadata(ctx context.Context, md metadata.MD) (*database.User, error) {
	if len(md.Get(rpc.TokenMetadataKey)) == 0 && len(md.Get(rpc.JwtTokenMetadataKey)) == 0 && len(md.Get(rpc.InternalTokenMetadataKey)) == 0 {
		return nil, ErrSessionNotFound
	}

	userId := ""
	if len(md.Get(rpc.TokenMetadataKey)) > 0 {
		tokenString := md.Get(rpc.TokenMetadataKey)[0]
		logger.Log.Debug("Found token")

		token, err := a.tokenDatabase.FindToken(ctx, tokenString)
		if err != nil {
			logger.Log.Info("Could not find token", slog.Any("error", err))
			return nil, ErrInvalidToken
		}
		userId = token.UserId
	} else if len(md.Get(rpc.JwtTokenMetadataKey)) > 0 {
		logger.Log.Debug("Found jwt token")
		j := md.Get(rpc.JwtTokenMetadataKey)[0]
		claims := &TokenClaims{}
		_, err := jwt.ParseWithClaims(j, claims, func(token *jwt.Token) (i any, e error) {
			if token.Method != jwt.SigningMethodES256 {
				return nil, xerrors.New("auth: invalid signing method")
			}
			return &a.publicKey, nil
		})
		if err != nil {
			logger.Log.Info("Failed parse jwt", slog.Any("error", err))
			return nil, ErrInvalidToken
		}
		if err := claims.Valid(); err != nil {
			logger.Log.Info("Invalid token", slog.Any("error", err))
			return nil, ErrInvalidToken
		}
		userId = claims.Subject
	} else if len(md.Get(rpc.InternalTokenMetadataKey)) > 0 {
		logger.Log.Debug("Found internal token")
		t := md.Get(rpc.InternalTokenMetadataKey)[0]
		if a.Config.AccessProxy.Credential.InternalToken != t {
			return nil, ErrInvalidToken
		}

		userId = database.SystemUser.Id
	}

	var rootUser *database.User
	for _, v := range a.Config.AuthorizationEngine.RootUsers {
		if v == userId {
			rootUser = &database.User{Id: userId, Admin: true, RootUser: true}
		}
	}

	user, err := a.userDatabase.Get(userId)
	if err != nil && rootUser == nil {
		logger.Log.Info("Could not find user", slog.Any("error", err), slog.String("user_id", userId))
		return nil, ErrUserNotFound
	}
	if user == nil && rootUser != nil {
		return rootUser, nil
	}
	if rootUser != nil {
		user.Admin = true
		user.RootUser = true
	}

	return user, nil
}

func tokenFromAuthorizationHeader(req *http.Request) (string, bool, error) {
	v := req.Header.Get("Authorization")
	scheme, credential, _ := strings.Cut(v, " ")
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		if credential == "" {
			return "", true, ErrInvalidToken
		}
		return credential, true, nil
	case strings.EqualFold(scheme, "Basic"):
		b, err := base64.StdEncoding.DecodeString(credential)
		if err != nil {
			return "", true, ErrInvalidToken
		}
		_, password, ok := strings.Cut(string(b), ":")
		if !ok || password == "" {
			return "", true, ErrInvalidToken
		}
		return password, true, nil
	default:
		return "", false, nil
	}
}

// HasTokenAuthorization reports whether the Authorization header of req is consumed by heimdallr as a token.
func HasTokenAuthorization(req *http.Request) bool {
	_, ok, _ := tokenFromAuthorizationHeader(req)
	return ok
}
