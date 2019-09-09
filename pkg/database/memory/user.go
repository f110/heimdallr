package memory

import (
	"context"
	"sync"

	"github.com/f110/lagrangian-proxy/pkg/database"
	"golang.org/x/xerrors"
)

type UserDatabase struct {
	mu   sync.Mutex
	data map[string]*database.User
}

func NewUserDatabase() *UserDatabase {
	return &UserDatabase{data: make(map[string]*database.User)}
}

func (u *UserDatabase) Get(_ctx context.Context, id string) (*database.User, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	v, ok := u.data[id]
	if !ok {
		return nil, xerrors.New("memory: user not found")
	}
	return v, nil
}

func (u *UserDatabase) Set(_ctx context.Context, user *database.User) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.data[user.Id] = user
	return nil
}
