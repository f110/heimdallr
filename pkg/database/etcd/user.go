package etcd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.f110.dev/xerrors"
	"go.uber.org/zap"
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
	client     *clientv3.Client
	cache      *Cache
	tokenCache *Cache
}

var _ database.UserDatabase = &UserDatabase{}

func NewUserDatabase(_ context.Context, client *clientv3.Client, systemUsers ...*database.User) (*UserDatabase, error) {
	initData := make([]*mvccpb.KeyValue, 0, len(systemUsers))
	for _, v := range systemUsers {
		value, err := database.MarshalUser(v)
		if err != nil {
			return nil, xerrors.WithStack(err)
		}
		kv := &mvccpb.KeyValue{
			Value:   value,
			Key:     []byte(fmt.Sprintf("user/%s", v.Id)),
			Version: 1,
		}
		initData = append(initData, kv)
	}

	u := &UserDatabase{
		client:     client,
		cache:      NewCache(client, "user/", initData),
		tokenCache: NewCache(client, "user_token/", nil),
	}
	go u.cache.Start(context.Background())
	go u.tokenCache.Start(context.Background())

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
			return nil, xerrors.WithStack(err)
		}
		if res.Count == 0 {
			return nil, database.ErrUserNotFound
		}
		user, err := database.UnmarshalUser(res.Kvs[0])
		if err != nil {
			return nil, err
		}
		return user, nil
	}

	all, err := d.cache.All()
	if err != nil {
		return nil, err
	}
	for _, v := range all {
		user, err := database.UnmarshalUser(v)
		if err != nil {
			return nil, err
		}

		if user.Id == id {
			return user, nil
		}
	}

	return nil, xerrors.WithStack(database.ErrUserNotFound)
}

func (d *UserDatabase) GetAll() ([]*database.User, error) {
	all, err := d.cache.All()
	if err != nil {
		return nil, err
	}

	users := make([]*database.User, 0, d.cache.Len())
	for _, v := range all {
		user, err := database.UnmarshalUser(v)
		if err != nil {
			return nil, err
		}

		users = append(users, user)
	}

	return users, nil
}

func (d *UserDatabase) GetIdentityByLoginName(_ context.Context, loginName string) (string, error) {
	all, err := d.cache.All()
	if err != nil {
		return "", err
	}

	for _, v := range all {
		user, err := database.UnmarshalUser(v)
		if err != nil {
			return "", err
		}
		if user.LoginName == loginName {
			return user.Id, nil
		}
	}

	return "", xerrors.WithStack(database.ErrUserNotFound)
}

func (d *UserDatabase) GetAllServiceAccount() ([]*database.User, error) {
	all, err := d.cache.All()
	if err != nil {
		return nil, err
	}

	users := make([]*database.User, 0, d.cache.Len())
	for _, v := range all {
		user, err := database.UnmarshalUser(v)
		if err != nil {
			return nil, err
		}
		if !user.ServiceAccount() {
			continue
		}

		users = append(users, user)
	}

	return users, nil
}

func (d *UserDatabase) GetAccessTokens(id string) ([]*database.AccessToken, error) {
	all, err := d.tokenCache.All()
	if err != nil {
		return nil, err
	}

	tokens := make([]*database.AccessToken, 0)
	for _, v := range all {
		token := &database.AccessToken{}
		if err := yaml.Unmarshal(v.Value, token); err != nil {
			continue
		}
		if token.UserId == id {
			tokens = append(tokens, token)
		}
	}

	return tokens, nil
}

func (d *UserDatabase) GetAccessToken(value string) (*database.AccessToken, error) {
	all, err := d.tokenCache.All()
	if err != nil {
		return nil, err
	}

	for _, v := range all {
		token := &database.AccessToken{}
		if err := yaml.Unmarshal(v.Value, token); err != nil {
			continue
		}
		if token.Value == value {
			return token, nil
		}
	}

	return nil, database.ErrAccessTokenNotFound
}

func (d *UserDatabase) Set(ctx context.Context, user *database.User) error {
	if user.Id == "" {
		return xerrors.NewWithStack("etcd: User.Id is required")
	}

	if !user.ServiceAccount() && len(user.Roles) == 0 {
		return d.Delete(ctx, user.Id)
	}

	b, err := database.MarshalUser(user)
	if err != nil {
		return err
	}

	res, err := d.client.Txn(ctx).
		If(clientv3.Compare(clientv3.Version(d.key(user.Id)), "=", user.Version)).
		Then(clientv3.OpPut(d.key(user.Id), string(b))).
		Commit()
	if err != nil {
		return xerrors.WithStack(err)
	}
	if !res.Succeeded {
		return xerrors.NewWithStack("etcd: Failed update database")
	}

	return nil
}

func (d *UserDatabase) SetAccessToken(ctx context.Context, token *database.AccessToken) error {
	b, err := yaml.Marshal(token)
	if err != nil {
		return xerrors.WithStack(err)
	}

	_, err = d.client.Put(ctx, fmt.Sprintf("user_token/%s", token.Value), string(b))
	if err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func (d *UserDatabase) Delete(ctx context.Context, id string) error {
	_, err := d.client.Delete(ctx, d.key(id))
	if err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func (d *UserDatabase) SetState(ctx context.Context, unique string) (string, error) {
	buf := make([]byte, 10)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", xerrors.WithMessage(err, "database: failure generate state")
	}
	stateString := base64.StdEncoding.EncodeToString(buf)

	s := &state{State: stateString[:len(stateString)-2], Unique: unique, CreatedAt: now()}
	b, err := yaml.Marshal(s)
	if err != nil {
		return "", xerrors.WithStack(err)
	}

	_, err = d.client.Put(ctx, fmt.Sprintf("user_state/%s", s.State), string(b))
	if err != nil {
		return "", xerrors.WithStack(err)
	}
	return s.State, nil
}

func (d *UserDatabase) GetState(ctx context.Context, stateString string) (string, error) {
	res, err := d.client.Get(ctx, fmt.Sprintf("user_state/%s", stateString))
	if err != nil {
		return "", xerrors.WithStack(err)
	}
	if res.Count == 0 {
		return "", xerrors.NewWithStack("database: state not found")
	}

	s := &state{}
	if err := yaml.Unmarshal(res.Kvs[0].Value, s); err != nil {
		return "", xerrors.WithStack(err)
	}
	if s.CreatedAt.Add(1 * time.Hour).Before(now()) {
		_, err := d.client.Delete(ctx, fmt.Sprintf("user_state/%s", stateString))
		if err != nil {
			logger.Log.Warn("failure delete state", zap.String("state", stateString))
		}

		return "", xerrors.NewWithStack("database: state not founds")
	}

	return s.Unique, nil
}

func (d *UserDatabase) DeleteState(ctx context.Context, state string) error {
	_, err := d.client.Delete(ctx, fmt.Sprintf("user_state/%s", state))
	if err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func (d *UserDatabase) key(id string) string {
	return fmt.Sprintf("user/%s", id)
}

func (d *UserDatabase) Close() {
	d.cache.Close()
	d.tokenCache.Close()
}
