package etcd

import (
	"context"
	"fmt"

	"github.com/coreos/etcd/clientv3"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/ghodss/yaml"
	"golang.org/x/xerrors"
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

	return u, nil
}

func (d *UserDatabase) key(email string) string {
	return fmt.Sprintf("user/%s", email)
}
