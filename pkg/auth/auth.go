package auth

import (
	"context"
	"net/http"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/session"
	"golang.org/x/xerrors"
)

var defaultAuthenticator = &authenticator{}

var (
	ErrHostnameNotFound = xerrors.New("auth: hostname not found")
	ErrSessionNotFound  = xerrors.New("auth: session not found")
	ErrUserNotFound     = xerrors.New("auth: user not found")
	ErrNotAllowed       = xerrors.New("auth: not allowed")
)

type SessionStore interface {
	GetSession(req *http.Request) (*session.Session, error)
}

type UserDatabase interface {
	Get(ctx context.Context, id string) (*database.User, error)
}

type authenticator struct {
	Conf         *config.General
	sessionStore SessionStore
	userDatabase UserDatabase
}

// Init is initializing authenticator. You must call first before calling Authenticate.
func Init() {}

func Authenticate(req *http.Request) (*database.User, error) {
	return defaultAuthenticator.Authenticate(req)
}

func (a *authenticator) Authenticate(req *http.Request) (*database.User, error) {
	backend, ok := a.Conf.GetBackendByHostname(req.Host)
	if !ok {
		return nil, ErrHostnameNotFound
	}

	user, err := a.findUser(req)
	if err != nil {
		return nil, err
	}

	matched := backend.MatchList(req)
	if len(matched) == 0 {
		return nil, ErrNotAllowed
	}
	for _, r := range user.Roles {
		role, err := a.Conf.GetRole(r)
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

func (a *authenticator) findUser(req *http.Request) (*database.User, error) {
	s, err := a.sessionStore.GetSession(req)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	u, err := a.userDatabase.Get(req.Context(), s.Id)
	if err != nil {
		return nil, ErrUserNotFound
	}

	return u, nil
}
