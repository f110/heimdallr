package memory

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"sync"

	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/database"
)

type UserDatabase struct {
	mu    sync.Mutex
	data  map[string]*database.User
	state map[string]string
}

var _ database.UserDatabase = &UserDatabase{}

func NewUserDatabase(systemUsers ...*database.User) *UserDatabase {
	data := make(map[string]*database.User)
	for _, v := range systemUsers {
		data[v.Id] = v
	}

	return &UserDatabase{
		data:  data,
		state: make(map[string]string),
	}
}

func (u *UserDatabase) Get(id string, _ ...database.UserDatabaseOption) (*database.User, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	v, ok := u.data[id]
	if !ok {
		return nil, xerrors.NewWithStack("memory: user not found")
	}
	return v, nil
}

func (u *UserDatabase) GetAll() ([]*database.User, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	users := make([]*database.User, 0, len(u.data))
	for _, v := range u.data {
		users = append(users, v)
	}

	return users, nil
}

func (u *UserDatabase) GetIdentityByLoginName(_ context.Context, loginName string) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	for _, v := range u.data {
		if v.LoginName == loginName {
			return v.Id, nil
		}
	}

	return "", xerrors.WithStack(database.ErrUserNotFound)
}

func (u *UserDatabase) GetAllServiceAccount() ([]*database.User, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	users := make([]*database.User, 0, len(u.data))
	for _, v := range u.data {
		if v.Type != database.UserTypeServiceAccount {
			continue
		}
		users = append(users, v)
	}

	return users, nil
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

func (u *UserDatabase) SetState(_ context.Context, unique string) (string, error) {
	buf := make([]byte, 10)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", xerrors.WithMessage(err, "database: failure generate state")
	}
	t := base64.StdEncoding.EncodeToString(buf)
	stateString := t[:len(t)-2]

	u.mu.Lock()
	u.state[stateString] = unique
	u.mu.Unlock()

	return stateString, nil
}

func (u *UserDatabase) GetState(_ context.Context, state string) (string, error) {
	u.mu.Lock()
	unique, ok := u.state[state]
	u.mu.Unlock()
	if !ok {
		return "", xerrors.NewWithStack("database: state not found")
	}

	return unique, nil
}

func (u *UserDatabase) DeleteState(_ context.Context, state string) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	delete(u.state, state)
	return nil
}
