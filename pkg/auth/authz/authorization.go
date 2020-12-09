package authz

import (
	"context"
	"net/http"
	"time"

	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/config"
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

var defaultAuthorization = &authorization{}

type authorization struct {
	Config *configv2.Config
}

func Init(conf *configv2.Config) {
	defaultAuthorization.Config = conf
}

func Authorization(ctx context.Context, req *http.Request, user *database.User, sess *session.Session) error {
	return defaultAuthorization.Authorization(ctx, req, user, sess)
}

func AuthorizationSocket(ctx context.Context, backend *configv2.Backend, user *database.User) error {
	return defaultAuthorization.AuthorizationSocket(ctx, backend, user)
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
		if err == config.ErrRoleNotFound {
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
		if err == config.ErrRoleNotFound {
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
