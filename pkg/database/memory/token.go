package memory

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"

	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/database"
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

func (t *TokenDatabase) SetUser(userId string) (*database.Token, error) {
	code, err := t.NewCode(nil, userId, "", "")
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	return t.IssueToken(nil, code.Code, "")
}

func (t *TokenDatabase) NewCode(_ context.Context, userId, _, _ string) (*database.Code, error) {
	s, err := newCode()
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	code := &database.Code{Code: s, UserId: userId}

	t.mu.Lock()
	t.codes[code.Code] = code
	t.mu.Unlock()

	return code, nil
}

func (t *TokenDatabase) IssueToken(_ context.Context, code, _ string) (*database.Token, error) {
	t.mu.Lock()
	v := t.codes[code]
	t.mu.Unlock()

	s, err := newCode()
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	token := &database.Token{Token: s}
	if v != nil {
		token.UserId = v.UserId
	}

	t.mu.Lock()
	t.tokens[token.Token] = token
	t.mu.Unlock()

	return token, nil
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

func newCode() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
