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
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"
)

type UserDatabase struct {
	client *clientv3.Client

	mu    sync.RWMutex
	users map[string]*database.User
}

var _ database.UserDatabase = &UserDatabase{}

func NewUserDatabase(ctx context.Context, client *clientv3.Client) (*UserDatabase, error) {
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

	u := &UserDatabase{client: client, users: users}
	go u.watchUser(ctx, res.Header.Revision)
	return u, nil
}

func (d *UserDatabase) Get(id string) (*database.User, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if v, ok := d.users[id]; ok {
		return v, nil
	} else {
		return nil, database.ErrUserNotFound
	}
}

func (d *UserDatabase) GetAll() []*database.User {
	d.mu.RLock()
	defer d.mu.RUnlock()

	users := make([]*database.User, 0, len(d.users))
	for _, v := range d.users {
		users = append(users, v)
	}

	return users
}

func (d *UserDatabase) Set(ctx context.Context, user *database.User) error {
	if user.Id == "" {
		return xerrors.New("etcd: User.Id is required")
	}

	if len(user.Roles) == 0 {
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
	watchCh := d.client.Watch(ctx, "user/", clientv3.WithPrefix(), clientv3.WithRev(revision))
	for {
		select {
		case res := <-watchCh:
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