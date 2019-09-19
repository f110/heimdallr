package auth

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/session"
	"golang.org/x/xerrors"
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

type authenticator struct {
	Config        *config.General
	sessionStore  session.Store
	userDatabase  database.UserDatabase
	ca            database.CertificateAuthority
	tokenDatabase database.TokenDatabase
}

// Init is initializing authenticator. You must call first before calling Authenticate.
func Init(conf *config.Config, sessionStore session.Store, userDatabase database.UserDatabase, ca database.CertificateAuthority, tokenDatabase database.TokenDatabase) {
	defaultAuthenticator.Config = conf.General
	defaultAuthenticator.sessionStore = sessionStore
	defaultAuthenticator.userDatabase = userDatabase
	defaultAuthenticator.ca = ca
	defaultAuthenticator.tokenDatabase = tokenDatabase
}

func Authenticate(req *http.Request) (*database.User, error) {
	return defaultAuthenticator.Authenticate(req)
}

func AuthenticateForSocket(ctx context.Context, token, host string) (*database.User, error) {
	return defaultAuthenticator.AuthenticateForSocket(ctx, token, host)
}

func (a *authenticator) Authenticate(req *http.Request) (*database.User, error) {
	backend, ok := a.Config.GetBackendByHost(req.Host)
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

	s, err := a.sessionStore.GetSession(req)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	u, err := a.userDatabase.Get(s.Id)
	if err != nil {
		return nil, ErrUserNotFound
	}

	return u, nil
}

func (a *authenticator) findUserByToken(token string) (*database.User, error) {
	return nil, ErrUserNotFound
}
