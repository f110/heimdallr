package memory

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"sync"

	"github.com/f110/lagrangian-proxy/pkg/database"
	"golang.org/x/xerrors"
)

type UserDatabase struct {
	mu        sync.Mutex
	data      map[string]*database.User
	tokenData map[string]*database.AccessToken
	state     map[string]string
}

var _ database.UserDatabase = &UserDatabase{}

func NewUserDatabase() *UserDatabase {
	return &UserDatabase{
		data:  make(map[string]*database.User),
		state: make(map[string]string),
	}
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

func (u *UserDatabase) GetAll() ([]*database.User, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	users := make([]*database.User, 0, len(u.data))
	for _, v := range u.data {
		if v.Type != database.UserTypeNormal {
			continue
		}
		users = append(users, v)
	}

	return users, nil
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

func (u *UserDatabase) GetAccessTokens(id string) ([]*database.AccessToken, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	tokens := make([]*database.AccessToken, 0)
	for _, v := range u.tokenData {
		if v.UserId == id {
			tokens = append(tokens, v)
		}
	}

	return tokens, nil
}

func (u *UserDatabase) GetAccessToken(value string) (*database.AccessToken, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if v, ok := u.tokenData[value]; ok {
		return v, nil
	}

	return nil, database.ErrAccessTokenNotFound
}

func (u *UserDatabase) Set(_ctx context.Context, user *database.User) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.data[user.Id] = user
	return nil
}

func (u *UserDatabase) SetAccessToken(_ context.Context, token *database.AccessToken) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.tokenData[token.Value] = token
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
		return "", xerrors.Errorf("database: failure generate state: %v", err)
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
		return "", xerrors.New("database: state not found")
	}

	return unique, nil
}

func (u *UserDatabase) DeleteState(_ context.Context, state string) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	delete(u.state, state)
	return nil
}
