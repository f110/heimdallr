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

	"github.com/coreos/etcd/clientv3"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"

	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
)

type UserDatabase struct {
	client *clientv3.Client

	mu     sync.RWMutex
	users  map[string]*database.User
	tokens map[string]*database.AccessToken
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

	u := &UserDatabase{client: client, users: users}
	go u.watchUser(ctx, res.Header.Revision)

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
	go u.watchToken(ctx, res.Header.Revision)

	return u, nil
}

func (d *UserDatabase) Get(id string) (*database.User, error) {
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

	return nil
}

func (d *UserDatabase) SetAccessToken(ctx context.Context, token *database.AccessToken) error {
	b, err := yaml.Marshal(token)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	_, err = d.client.Put(ctx, fmt.Sprintf("user_token/%s", token.Value), string(b))
	return err
}

func (d *UserDatabase) Delete(ctx context.Context, id string) error {
	_, err := d.client.Delete(ctx, d.key(id))
	if err != nil {
		return xerrors.Errorf(": $v", err)
	}
	return nil
}

type state struct {
	State     string
	Unique    string
	CreatedAt time.Time
}

func (d *UserDatabase) SetState(ctx context.Context, unique string) (string, error) {
	buf := make([]byte, 10)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", xerrors.Errorf("database: failure generate state: %v", err)
	}
	stateString := base64.StdEncoding.EncodeToString(buf)

	s := &state{State: stateString[:len(stateString)-2], Unique: unique, CreatedAt: time.Now()}
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
	if s.CreatedAt.Add(1 * time.Hour).Before(time.Now()) {
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

func (d *UserDatabase) key(id string) string {
	return fmt.Sprintf("user/%s", id)
}

func (d *UserDatabase) watchUser(ctx context.Context, revision int64) {
	logger.Log.Debug("Start watching users")
	defer d.close()

	watchCh := d.client.Watch(ctx, "user/", clientv3.WithPrefix(), clientv3.WithRev(revision))
Watch:
	for {
		select {
		case res, ok := <-watchCh:
			if !ok {
				break Watch
			}
			for _, event := range res.Events {
				switch event.Type {
				case clientv3.EventTypePut:
					user, err := database.UnmarshalUser(event.Kv)
					if err != nil {
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
						logger.Log.Warn("User not found", zap.String("id", id))
						d.mu.Unlock()
						continue
					}
					delete(d.users, id)
					d.mu.Unlock()
					logger.Log.Debug("Remove user", zap.String("id", id))
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func (d *UserDatabase) watchToken(ctx context.Context, revision int64) {
	logger.Log.Debug("Start watching tokens")
	defer d.close()

	watchCh := d.client.Watch(ctx, "user_token/", clientv3.WithPrefix(), clientv3.WithRev(revision))
Watch:
	for {
		select {
		case res, ok := <-watchCh:
			if !ok {
				break Watch
			}
			for _, event := range res.Events {
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
		case <-ctx.Done():
			return
		}
	}
}

func (d *UserDatabase) close() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.users = nil
	d.tokens = nil
}
