package authz

import (
	"context"
	"errors"
	"net/http"
	"time"

	"go.f110.dev/xerrors"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/session"
)

var (
	ErrHostnameNotFound = xerrors.New("authz: hostname not found")
	ErrSessionNotFound  = xerrors.New("authz: session not found")
	ErrNotAllowed       = xerrors.New("authz: not allowed")
)

var DefaultAuthorization = &authorization{}

type authorization struct {
	Config *configv2.Config
}

func Init(conf *configv2.Config) {
	DefaultAuthorization.Config = conf
}

func Authorization(ctx context.Context, req *http.Request, user *database.User, sess *session.Session) error {
	return DefaultAuthorization.Authorization(ctx, req, user, sess)
}

func AuthorizationSocket(ctx context.Context, backend *configv2.Backend, user *database.User) error {
	return DefaultAuthorization.AuthorizationSocket(ctx, backend, user)
}

func (a *authorization) Authorization(_ context.Context, req *http.Request, user *database.User, sess *session.Session) error {
	backend, ok := a.Config.AccessProxy.GetBackendByHost(req.Host)
	if !ok {
		return ErrHostnameNotFound
	}
	if backend.DisableAuthn {
		if len(backend.Permissions) == 0 {
			return nil
		}

		matched := backend.MatchList(req)
		if len(matched) == 0 {
			return ErrNotAllowed
		}
		return nil
	}

	if backend.AllowRootUser && user.RootUser {
		return nil
	}

	checkPermission := false
	matched := backend.MatchList(req)
	if len(matched) == 0 {
		return ErrNotAllowed
	}
	for _, r := range user.Roles {
		role, err := a.Config.AuthorizationEngine.GetRole(r)
		if errors.Is(err, configv2.ErrRoleNotFound) {
			continue
		}
		if err != nil {
			continue
		}
		for _, b := range role.Bindings {
			if b.Backend == backend.Name {
				if _, ok := matched[b.Permission]; ok {
					checkPermission = true
					break
				}
			}
		}
	}
	if !checkPermission {
		logger.Log.Debug("User not permitted", zap.String("user", user.Id), zap.Strings("roles", user.Roles))
		return ErrNotAllowed
	}

	if backend.MaxSessionDuration != nil {
		if sess == nil {
			return ErrSessionNotFound
		}

		if time.Now().After(sess.IssuedAt.Add(backend.MaxSessionDuration.Duration)) {
			logger.Log.Debug("User authenticated but session is expired", zap.Time("issued_at", sess.IssuedAt))
			return ErrSessionNotFound
		}
	}

	return nil
}

func (a *authorization) AuthorizationSocket(_ context.Context, backend *configv2.Backend, user *database.User) error {
	for _, r := range user.Roles {
		role, err := a.Config.AuthorizationEngine.GetRole(r)
		if err == configv2.ErrRoleNotFound {
			continue
		}
		if err != nil {
			continue
		}

		for _, b := range role.Bindings {
			if b.Backend == backend.Name {
				return nil
			}
		}
	}

	return ErrNotAllowed
}

func (a *authorization) UnaryCall(info *grpc.UnaryServerInfo, user *database.User) error {
	ok := false
	for _, v := range user.Roles {
		role, err := a.Config.AuthorizationEngine.GetRole(v)
		if err != nil {
			continue
		}
		if v := role.RPCMethodMatcher.Match(info.FullMethod); v {
			ok = true
			break
		}
	}
	if !ok && user.RootUser {
		ok = true
	}
	if !ok {
		logger.Log.Info("User doesn't have privilege", zap.String("user_id", user.Id), zap.String("method", info.FullMethod))
		return ErrNotAllowed
	}

	return nil
}
