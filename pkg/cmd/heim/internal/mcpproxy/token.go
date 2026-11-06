package mcpproxy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/config/userconfig"
)

// LoginFunc obtains a new token from the token endpoint. It is expected to open the browser and wait for the authorization.
type LoginFunc func(ctx context.Context, endpoint string) (token string, expiresAt time.Time, err error)

// TokenSource provides the access token stored in the user directory.
// When the stored token is expired or rejected, TokenSource runs LoginFunc.
// Concurrent callers share one login.
type TokenSource struct {
	userDir      *userconfig.UserDir
	server       string
	login        LoginFunc
	loginTimeout time.Duration

	mu sync.Mutex
}

// NewTokenSource returns TokenSource.
// server is the hostname of the token server. If server is empty, the endpoint of the stored token is used.
func NewTokenSource(userDir *userconfig.UserDir, server string, login LoginFunc, loginTimeout time.Duration) *TokenSource {
	return &TokenSource{userDir: userDir, server: server, login: login, loginTimeout: loginTimeout}
}

// Token returns the valid token.
func (s *TokenSource) Token(ctx context.Context) (string, error) {
	return s.token(ctx, "")
}

// Renew returns the token which is different from rejected.
func (s *TokenSource) Renew(ctx context.Context, rejected string) (string, error) {
	return s.token(ctx, rejected)
}

func (s *TokenSource) token(ctx context.Context, rejected string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, err := s.userDir.GetToken()
	if err != nil {
		return "", err
	}
	if !stored.IsExpired() && stored.Token != rejected {
		return stored.Token, nil
	}

	endpoint := ""
	switch {
	case s.server != "":
		endpoint = fmt.Sprintf("https://%s/token", s.server)
	case stored != nil && stored.Endpoint != "":
		endpoint = stored.Endpoint
	default:
		return "", xerrors.New("the token server is unknown. specify --server")
	}

	loginCtx, cancel := context.WithTimeout(ctx, s.loginTimeout)
	defer cancel()
	t, expiresAt, err := s.login(loginCtx, endpoint)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return "", xerrors.Newf("the authentication did not complete in %s", s.loginTimeout)
		}
		return "", err
	}
	if err := s.userDir.SetToken(endpoint, t, expiresAt); err != nil {
		return "", err
	}

	return t, nil
}
