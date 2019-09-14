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

var _ database.UserDatabase = &UserDatabase{}

func NewUserDatabase() *UserDatabase {
	return &UserDatabase{data: make(map[string]*database.User)}
}

func (u *UserDatabase) Get(id string) (*database.User, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	v, ok := u.data[id]
	if !ok {
		return nil, xerrors.New("memory: user not found")
	}
	return v, nil
}

func (u *UserDatabase) GetAll() []*database.User {
	u.mu.Lock()
	defer u.mu.Unlock()

	users := make([]*database.User, 0, len(u.data))
	for _, v := range u.data {
		users = append(users, v)
	}

	return users
}

func (u *UserDatabase) Set(_ctx context.Context, user *database.User) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.data[user.Id] = user
	return nil
}

func (u *UserDatabase) Delete(_ctx context.Context, id string) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	delete(u.data, id)
	return nil
}
