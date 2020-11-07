package etcd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"go.etcd.io/etcd/v3/clientv3"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
)

// For testing hack
var now = time.Now

type state struct {
	State     string
	Unique    string
	CreatedAt time.Time
}

type UserDatabase struct {
	client *clientv3.Client

	mu     sync.RWMutex
	users  map[string]*database.User
	tokens map[string]*database.AccessToken

	watchCtx    context.Context
	watchCancel context.CancelFunc
}

var _ database.UserDatabase = &UserDatabase{}

func NewUserDatabase(ctx context.Context, client *clientv3.Client, systemUsers ...*database.User) (*UserDatabase, error) {
	res, err := client.Get(ctx, "user/", clientv3.WithPrefix())
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	allUser := make([]*database.User, 0, res.Count)
	for _, v := range res.Kvs {
		user, err := database.UnmarshalUser(v)
		if err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}

		allUser = append(allUser, user)
	}
	users := make(map[string]*database.User)
	for _, v := range allUser {
		users[v.Id] = v
	}
	for _, v := range systemUsers {
		users[v.Id] = v
	}

	watchCtx, watchCancel := context.WithCancel(context.Background())
	u := &UserDatabase{client: client, users: users, watchCtx: watchCtx, watchCancel: watchCancel}
	go u.watchUser(res.Header.Revision)

	res, err = client.Get(ctx, "user_token/", clientv3.WithPrefix())
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	tokens := make([]*database.AccessToken, 0, res.Count)
	for _, v := range res.Kvs {
		token := &database.AccessToken{}
		if err := yaml.Unmarshal(v.Value, token); err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}
		tokens = append(tokens, token)
	}
	t := make(map[string]*database.AccessToken)
	for _, v := range tokens {
		t[v.Value] = v
	}
	u.tokens = t
	go u.watchToken(res.Header.Revision)

	return u, nil
}

func (d *UserDatabase) Get(id string, opts ...database.UserDatabaseOption) (*database.User, error) {
	opt := &database.UserDatabaseOpt{}
	for _, v := range opts {
		v(opt)
	}
	if opt.WithoutCache {
		if id == database.SystemUser.Id {
			return database.SystemUser, nil
		}
		res, err := d.client.Get(context.Background(), d.key(id))
		if err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}
		if res.Count == 0 {
			return nil, database.ErrUserNotFound
		}
		user, err := database.UnmarshalUser(res.Kvs[0])
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		return user, nil
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.users == nil {
		return nil, database.ErrClosed
	}

	if v, ok := d.users[id]; ok {
		return v, nil
	} else {
		return nil, database.ErrUserNotFound
	}
}

func (d *UserDatabase) GetAll() ([]*database.User, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.users == nil {
		return nil, database.ErrClosed
	}

	users := make([]*database.User, 0, len(d.users))
	for _, v := range d.users {
		users = append(users, v)
	}

	return users, nil
}

func (d *UserDatabase) GetIdentityByLoginName(_ context.Context, loginName string) (string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	for _, v := range d.users {
		if v.LoginName == loginName {
			return v.Id, nil
		}
	}

	return "", database.ErrUserNotFound
}

func (d *UserDatabase) GetAllServiceAccount() ([]*database.User, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.users == nil {
		return nil, database.ErrClosed
	}

	users := make([]*database.User, 0, len(d.users))
	for _, v := range d.users {
		if !v.ServiceAccount() {
			continue
		}
		users = append(users, v)
	}

	return users, nil
}

func (d *UserDatabase) GetAccessTokens(id string) ([]*database.AccessToken, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.tokens == nil {
		return nil, database.ErrClosed
	}

	tokens := make([]*database.AccessToken, 0)
	for _, v := range d.tokens {
		if v.UserId == id {
			tokens = append(tokens, v)
		}
	}

	return tokens, nil
}

func (d *UserDatabase) GetAccessToken(value string) (*database.AccessToken, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.tokens == nil {
		return nil, database.ErrClosed
	}

	if v, ok := d.tokens[value]; ok {
		return v, nil
	}

	return nil, database.ErrAccessTokenNotFound
}

func (d *UserDatabase) Set(ctx context.Context, user *database.User) error {
	if user.Id == "" {
		return xerrors.New("etcd: User.Id is required")
	}

	if !user.ServiceAccount() && len(user.Roles) == 0 {
		return d.Delete(ctx, user.Id)
	}

	b, err := database.MarshalUser(user)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	res, err := d.client.Txn(ctx).
		If(clientv3.Compare(clientv3.Version(d.key(user.Id)), "=", user.Version)).
		Then(clientv3.OpPut(d.key(user.Id), string(b))).
		Commit()
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if !res.Succeeded {
		return xerrors.New("etcd: Failed update database")
	}

	d.mu.Lock()
	d.users[user.Id] = user
	d.mu.Unlock()

	return nil
}

func (d *UserDatabase) SetAccessToken(ctx context.Context, token *database.AccessToken) error {
	b, err := yaml.Marshal(token)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	_, err = d.client.Put(ctx, fmt.Sprintf("user_token/%s", token.Value), string(b))
	if err != nil {
		return err
	}

	d.mu.Lock()
	d.tokens[token.Value] = token
	d.mu.Unlock()

	return nil
}

func (d *UserDatabase) Delete(ctx context.Context, id string) error {
	_, err := d.client.Delete(ctx, d.key(id))
	if err != nil {
		return xerrors.Errorf(": $v", err)
	}

	d.mu.Lock()
	delete(d.users, id)
	d.mu.Unlock()

	return nil
}

func (d *UserDatabase) SetState(ctx context.Context, unique string) (string, error) {
	buf := make([]byte, 10)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", xerrors.Errorf("database: failure generate state: %v", err)
	}
	stateString := base64.StdEncoding.EncodeToString(buf)

	s := &state{State: stateString[:len(stateString)-2], Unique: unique, CreatedAt: now()}
	b, err := yaml.Marshal(s)
	if err != nil {
		return "", xerrors.Errorf(": %v", err)
	}

	_, err = d.client.Put(ctx, fmt.Sprintf("user_state/%s", s.State), string(b))
	if err != nil {
		return "", xerrors.Errorf(": %v", err)
	}
	return s.State, nil
}

func (d *UserDatabase) GetState(ctx context.Context, stateString string) (string, error) {
	res, err := d.client.Get(ctx, fmt.Sprintf("user_state/%s", stateString))
	if err != nil {
		return "", xerrors.Errorf(": %v", err)
	}
	if res.Count == 0 {
		return "", xerrors.New("database: state not found")
	}

	s := &state{}
	if err := yaml.Unmarshal(res.Kvs[0].Value, s); err != nil {
		return "", xerrors.Errorf(": %v", err)
	}
	if s.CreatedAt.Add(1 * time.Hour).Before(now()) {
		_, err := d.client.Delete(ctx, fmt.Sprintf("user_state/%s", stateString))
		if err != nil {
			logger.Log.Warn("failure delete state", zap.String("state", stateString))
		}

		return "", xerrors.New("database: state not founds")
	}

	return s.Unique, nil
}

func (d *UserDatabase) DeleteState(ctx context.Context, state string) error {
	_, err := d.client.Delete(ctx, fmt.Sprintf("user_state/%s", state))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	return nil
}

func (d *UserDatabase) SetSSHKeys(ctx context.Context, keys *database.SSHKeys) error {
	b, err := yaml.Marshal(keys)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	_, err = d.client.Put(ctx, fmt.Sprintf("ssh_keys/%s", keys.UserId), string(b))
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (d *UserDatabase) GetSSHKeys(ctx context.Context, id string) (*database.SSHKeys, error) {
	res, err := d.client.Get(ctx, fmt.Sprintf("ssh_keys/%s", id))
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if res.Count == 0 {
		return nil, xerrors.New("database: ssh keys not found")
	}

	keys := &database.SSHKeys{}
	if err := yaml.Unmarshal(res.Kvs[0].Value, keys); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return keys, nil
}

func (d *UserDatabase) SetGPGKey(ctx context.Context, key *database.GPGKey) error {
	b, err := yaml.Marshal(key)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	_, err = d.client.Put(ctx, fmt.Sprintf("gpg_key/%s", key.UserId), string(b))
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (d *UserDatabase) GetGPGKey(ctx context.Context, id string) (*database.GPGKey, error) {
	res, err := d.client.Get(ctx, fmt.Sprintf("gpg_key/%s", id))
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if res.Count == 0 {
		return nil, xerrors.New("database: ssh keys not found")
	}

	keys := &database.GPGKey{}
	if err := yaml.Unmarshal(res.Kvs[0].Value, keys); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return keys, nil
}

func (d *UserDatabase) key(id string) string {
	return fmt.Sprintf("user/%s", id)
}

func (d *UserDatabase) watchUser(revision int64) {
	logger.Log.Debug("Start watching users")
	defer d.Close()

	watchCh := d.client.Watch(d.watchCtx, "user/", clientv3.WithPrefix(), clientv3.WithRev(revision))
Watch:
	for {
		select {
		case res, ok := <-watchCh:
			if !ok {
				break Watch
			}
			d.watchUserEvent(res.Events)
		case <-d.watchCtx.Done():
		}
	}
}

func (d *UserDatabase) watchUserEvent(events []*clientv3.Event) {
	for _, event := range events {
		switch event.Type {
		case clientv3.EventTypePut:
			user, err := database.UnmarshalUser(event.Kv)
			if err != nil {
				logger.Log.Debug("Failed parse KVS", zap.Error(err))
				continue
			}
			if user.Id == "" {
				logger.Log.Info("Failed parse value", zap.ByteString("value", event.Kv.Value))
				continue
			}

			d.mu.Lock()
			d.users[user.Id] = user
			d.mu.Unlock()
			logger.Log.Debug("Add new user", zap.String("id", user.Id))
		case clientv3.EventTypeDelete:
			key := strings.Split(string(event.Kv.Key), "/")
			id := key[len(key)-1]
			d.mu.Lock()
			if _, ok := d.users[id]; !ok {
				logger.Log.Debug("User not found", zap.String("id", id))
				d.mu.Unlock()
				continue
			}
			delete(d.users, id)
			d.mu.Unlock()
			logger.Log.Debug("Remove user", zap.String("id", id))
		}
	}
}

func (d *UserDatabase) watchToken(revision int64) {
	logger.Log.Debug("Start watching tokens")
	defer d.Close()

	watchCh := d.client.Watch(d.watchCtx, "user_token/", clientv3.WithPrefix(), clientv3.WithRev(revision))
Watch:
	for {
		select {
		case res, ok := <-watchCh:
			if !ok {
				break Watch
			}
			d.watchTokenEvent(res.Events)
		case <-d.watchCtx.Done():
			return
		}
	}
}

func (d *UserDatabase) watchTokenEvent(events []*clientv3.Event) {
	for _, event := range events {
		switch event.Type {
		case clientv3.EventTypePut:
			token := &database.AccessToken{}
			if err := yaml.Unmarshal(event.Kv.Value, token); err != nil {
				continue
			}
			if token.Value == "" {
				logger.Log.Info("Failed parse value", zap.ByteString("value", event.Kv.Value))
				continue
			}

			d.mu.Lock()
			d.tokens[token.Value] = token
			d.mu.Unlock()
			logger.Log.Debug("Add new token", zap.String("value", token.Value))
		case clientv3.EventTypeDelete:
			key := strings.Split(string(event.Kv.Key), "/")
			value := key[len(key)-1]
			d.mu.Lock()
			if _, ok := d.tokens[value]; !ok {
				logger.Log.Warn("Token not found", zap.String("value", value))
				d.mu.Unlock()
				continue
			}
			delete(d.tokens, value)
			d.mu.Unlock()
			logger.Log.Debug("Remove token", zap.String("value", value))
		}
	}
}

func (d *UserDatabase) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.watchCancel()
	d.users = nil
	d.tokens = nil
}
