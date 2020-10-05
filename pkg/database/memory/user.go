package memory

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"sync"

	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/database"
)

type UserDatabase struct {
	mu        sync.Mutex
	data      map[string]*database.User
	tokenData map[string]*database.AccessToken
	state     map[string]string
	sshKeys   map[string]*database.SSHKeys
	gpgKey    map[string]*database.GPGKey
}

var _ database.UserDatabase = &UserDatabase{}

func NewUserDatabase(systemUsers ...*database.User) *UserDatabase {
	data := make(map[string]*database.User)
	for _, v := range systemUsers {
		data[v.Id] = v
	}

	return &UserDatabase{
		data:      data,
		tokenData: make(map[string]*database.AccessToken),
		state:     make(map[string]string),
		sshKeys:   make(map[string]*database.SSHKeys),
	}
}

func (u *UserDatabase) Get(id string, _ ...database.UserDatabaseOption) (*database.User, error) {
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

func (u *UserDatabase) GetSSHKeys(_ context.Context, id string) (*database.SSHKeys, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	v, ok := u.sshKeys[id]
	if !ok {
		return nil, xerrors.New("database: ssh keys not found")
	}

	return v, nil
}

func (u *UserDatabase) SetSSHKeys(_ context.Context, keys *database.SSHKeys) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.sshKeys[keys.UserId] = keys

	return nil
}
func (u *UserDatabase) GetGPGKey(_ context.Context, id string) (*database.GPGKey, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	v, ok := u.gpgKey[id]
	if !ok {
		return nil, xerrors.New("database: ssh keys not found")
	}

	return v, nil
}

func (u *UserDatabase) SetGPGKey(_ context.Context, key *database.GPGKey) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.gpgKey[key.UserId] = key

	return nil
}
