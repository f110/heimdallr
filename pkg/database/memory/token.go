package memory

import (
	"context"
	"sync"

	"github.com/f110/lagrangian-proxy/pkg/database"
)

type TokenDatabase struct {
	mu     sync.RWMutex
	tokens map[string]*database.Token
}

func NewTokenDatabase() *TokenDatabase {
	return &TokenDatabase{}
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
