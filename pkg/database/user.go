package database

import (
	"context"

	"github.com/coreos/etcd/mvcc/mvccpb"
	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"
)

var (
	ErrUserNotFound = xerrors.New("database: user not found")
)

type UserDatabase interface {
	Get(id string) (*User, error)
	GetAll() []*User
	Set(ctx context.Context, user *User) error
	Delete(ctx context.Context, id string) error
}

type User struct {
	Id            string          `json:"id"`
	Roles         []string        `json:"roles"`
	MaintainRoles map[string]bool `json:"maintain_roles,omitempty"`

	Version int64 `json:"-"`
}

func (u *User) Setup() {
	if u.Roles == nil {
		u.Roles = make([]string, 0)
	}
	if u.MaintainRoles == nil {
		u.MaintainRoles = make(map[string]bool)
	}
}

func UnmarshalUser(kv *mvccpb.KeyValue) (*User, error) {
	user := &User{}
	if err := yaml.Unmarshal(kv.Value, user); err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	user.Version = kv.Version
	user.Setup()

	return user, nil
}

func MarshalUser(user *User) ([]byte, error) {
	b, err := yaml.Marshal(user)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	return b, nil
}
