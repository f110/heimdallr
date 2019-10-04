package memory

import (
	"context"
	"sync"

	"github.com/f110/lagrangian-proxy/pkg/database"
)

type TokenDatabase struct {
	mu     sync.RWMutex
	tokens map[string]*database.Token
	codes  map[string]*database.Code
}

var _ database.TokenDatabase = &TokenDatabase{}

func NewTokenDatabase() *TokenDatabase {
	return &TokenDatabase{
		tokens: make(map[string]*database.Token),
		codes:  make(map[string]*database.Code),
	}
}

func (t *TokenDatabase) NewCode(ctx context.Context, userId, challenge, challengeMethod string) (*database.Code, error) {
	panic("implement me")
}

func (t *TokenDatabase) IssueToken(ctx context.Context, code, codeVerifier string) (*database.Token, error) {
	panic("implement me")
}

func (t *TokenDatabase) AllCodes(_ context.Context) ([]*database.Code, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]*database.Code, 0)
	for _, v := range t.codes {
		result = append(result, v)
	}

	return result, nil
}

func (t *TokenDatabase) FindToken(_ context.Context, token string) (*database.Token, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	v, ok := t.tokens[token]
	if !ok {
		return nil, database.ErrTokenNotFound
	}
	return v, nil
}

func (t *TokenDatabase) DeleteCode(_ context.Context, code string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.codes, code)
	return nil
}

func (t *TokenDatabase) AllTokens(_ context.Context) ([]*database.Token, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]*database.Token, 0)
	for _, v := range t.tokens {
		result = append(result, v)
	}

	return result, nil
}

func (t *TokenDatabase) DeleteToken(_ context.Context, token string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.tokens, token)
	return nil
}
