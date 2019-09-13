package etcd

import (
	"context"
	"fmt"

	"github.com/coreos/etcd/clientv3"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"
)

type UserDatabase struct {
	client *clientv3.Client
}

func NewUserDatabase(client *clientv3.Client) *UserDatabase {
	return &UserDatabase{client: client}
}

func (d *UserDatabase) Get(ctx context.Context, id string) (*database.User, error) {
	res, err := d.client.Get(ctx, d.key(id))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	if res.Count == 0 {
		return nil, database.ErrUserNotFound
	}

	u := &database.User{}
	if err := yaml.Unmarshal(res.Kvs[0].Value, u); err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	u.Version = res.Kvs[0].Version
	u.Setup()

	return u, nil
}

func (d *UserDatabase) GetAll(ctx context.Context) ([]*database.User, error) {
	res, err := d.client.Get(ctx, "user/", clientv3.WithPrefix())
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	users := make([]*database.User, 0, res.Count)
	for _, v := range res.Kvs {
		user := &database.User{}
		if err := yaml.Unmarshal(v.Value, user); err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}
		user.Version = v.Version
		user.Setup()
		users = append(users, user)
	}

	return users, nil
}

func (d *UserDatabase) Set(ctx context.Context, user *database.User) error {
	if user.Id == "" {
		return xerrors.New("etcd: User.Id is required")
	}

	if len(user.Roles) == 0 {
		return d.Delete(ctx, user.Id)
	}

	b, err := yaml.Marshal(user)
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

func (d *UserDatabase) key(id string) string {
	return fmt.Sprintf("user/%s", id)
}
