package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
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

func (a *authentication) Authenticate(ctx context.Context, req *http.Request) (*database.User, *session.Session, error) {
	backend, ok := a.Config.AccessProxy.GetBackendByHost(req.Host)
	if !ok {
		return nil, nil, ErrHostnameNotFound
	}
	if backend.DisableAuthn {
		if len(backend.Permissions) == 0 {
			return &database.User{}, nil, nil
		}

		matched := backend.MatchList(req)
		if len(matched) == 0 {
			return nil, nil, ErrNotAllowed
		}
		return &database.User{}, nil, nil
	}

	user, sess, err := a.findUser(ctx, req)
	if err == ErrUserNotFound {
		u, s, rErr := a.findRootUser(req)
		if rErr != nil {
			return nil, nil, err
		}
		return u, s, nil
	} else if err != nil {
		return nil, nil, err
	}

	return user, sess, nil
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

	t, err := a.tokenDatabase.FindToken(ctx, token)
	if err != nil {
		return nil, nil, ErrInvalidToken
	}
	user, err := a.userDatabase.Get(t.UserId)
	if err != nil {
		return nil, nil, ErrUserNotFound
	}

	return backend, user, nil
}

func (a *authentication) UnaryCall(ctx context.Context) (*database.User, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		logger.Log.Info("Can't get metadata from incoming context")
		return nil, ErrSessionNotFound
	}

	user, err := a.authenticateByMetadata(ctx, md)
	if err != nil {
		logger.Log.Info("Failed request authentication", zap.Error(err))
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
		logger.Log.Info("Failed request authentication", zap.Error(err))
		return nil, ErrSessionNotFound
	}

	return user, nil
}

func (a *authentication) findUser(ctx context.Context, req *http.Request) (*database.User, *session.Session, error) {
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		logger.Log.Debug("Client Certificate authorization", logger.WithRequestId(ctx))
		// Client Certificate Authorization
		cert := req.TLS.PeerCertificates[0]
		if time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
			logger.Log.Debug("Expired certificate", logger.WithRequestId(ctx))
			return nil, nil, ErrInvalidCertificate
		}
		_, err := cert.Verify(x509.VerifyOptions{
			Roots:     a.Config.CertificateAuthority.CertPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			logger.Log.Debug("Failure verify certificate", zap.Error(err), logger.WithRequestId(ctx))
			return nil, nil, ErrInvalidCertificate
		}

		u, err := a.userDatabase.Get(cert.Subject.CommonName)
		if err != nil {
			return nil, nil, ErrUserNotFound
		}

		revoked := a.revokedCert.Get()
		for _, r := range revoked {
			if r.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				logger.Log.Debug("Revoked certificate", logger.WithRequestId(ctx))
				return nil, nil, ErrInvalidCertificate
			}
		}

		// Session by cookie is an optional
		s, err := a.sessionStore.GetSession(req)
		if err != nil {
			return u, nil, nil
		}

		return u, s, nil
	}

	if v := req.Header.Get("Authorization"); v == "LP-TOKEN" {
		token := req.Header.Get("X-LP-Token")
		if token == "" {
			return nil, nil, ErrUserNotFound
		}
		at, err := a.userDatabase.GetAccessToken(token)
		if err != nil {
			return nil, nil, ErrUserNotFound
		}
		user, err := a.userDatabase.Get(at.UserId)
		if err != nil {
			return nil, nil, ErrUserNotFound
		}

		return user, &session.Session{
			Id:       at.UserId,
			IssuedAt: at.CreatedAt,
		}, nil
	}

	s, err := a.sessionStore.GetSession(req)
	if err != nil {
		logger.Log.Debug("Failed get session", zap.Error(err))
		return nil, nil, ErrSessionNotFound
	}
	if s.Id == "" {
		logger.Log.Debug("Got session but id is empty")
		return nil, nil, ErrSessionNotFound
	}
	u, err := a.userDatabase.Get(s.Id)
	if err != nil {
		return nil, nil, ErrUserNotFound
	}

	return u, s, nil
}

func (a *authentication) findRootUser(req *http.Request) (*database.User, *session.Session, error) {
	s, err := a.sessionStore.GetSession(req)
	if err != nil {
		return nil, nil, ErrSessionNotFound
	}
	if s.Id == "" {
		return nil, nil, ErrSessionNotFound
	}

	asRootUser := false
	for _, v := range a.Config.AuthorizationEngine.RootUsers {
		if v == s.Id {
			asRootUser = true
			break
		}
	}
	if !asRootUser {
		return nil, nil, ErrUserNotFound
	}

	return &database.User{
		Id:       s.Id,
		RootUser: true,
	}, s, nil
}

func (a *authentication) authenticateByMetadata(ctx context.Context, md metadata.MD) (*database.User, error) {
	if len(md.Get(rpc.TokenMetadataKey)) == 0 && len(md.Get(rpc.JwtTokenMetadataKey)) == 0 && len(md.Get(rpc.InternalTokenMetadataKey)) == 0 {
		return nil, ErrSessionNotFound
	}

	userId := ""
	if len(md.Get(rpc.TokenMetadataKey)) > 0 {
		tokenString := md.Get(rpc.TokenMetadataKey)[0]
		logger.Log.Debug("Found token", zap.String("token", tokenString))

		token, err := a.tokenDatabase.FindToken(ctx, tokenString)
		if err != nil {
			logger.Log.Info("Could not find token", zap.Error(err))
			return nil, ErrInvalidToken
		}
		userId = token.UserId
	} else if len(md.Get(rpc.JwtTokenMetadataKey)) > 0 {
		logger.Log.Debug("Found jwt token", zap.String("token", md.Get(rpc.JwtTokenMetadataKey)[0]))
		j := md.Get(rpc.JwtTokenMetadataKey)[0]
		claims := &TokenClaims{}
		_, err := jwt.ParseWithClaims(j, claims, func(token *jwt.Token) (i interface{}, e error) {
			if token.Method != jwt.SigningMethodES256 {
				return nil, xerrors.New("auth: invalid signing method")
			}
			return &a.publicKey, nil
		})
		if err != nil {
			logger.Log.Info("Failed parse jwt", zap.Error(err))
			return nil, ErrInvalidToken
		}
		if err := claims.Valid(); err != nil {
			logger.Log.Info("Invalid token", zap.Error(err))
			return nil, ErrInvalidToken
		}
		userId = claims.Id
	} else if len(md.Get(rpc.InternalTokenMetadataKey)) > 0 {
		logger.Log.Debug("Found internal token", zap.String("token", md.Get(rpc.InternalTokenMetadataKey)[0]))
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
		logger.Log.Info("Could not find user", zap.Error(err), zap.String("user_id", userId))
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
