package database

import (
	"context"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"
)

var (
	ErrUserNotFound        = xerrors.New("database: user not found")
	ErrClosed              = xerrors.New("database: closed")
	ErrAccessTokenNotFound = xerrors.New("database: access token not found")
)

const (
	UserTypeServiceAccount = "service_account"
	UserTypeNormal         = "user"
)

var SystemUser = &User{
	Id:    "system@f110.dev",
	Roles: []string{"system:proxy"},
	Type:  UserTypeServiceAccount,
}

type UserDatabaseOpt struct {
	WithoutCache bool
}

type UserDatabaseOption func(*UserDatabaseOpt)

func WithoutCache(opt *UserDatabaseOpt) {
	opt.WithoutCache = true
}

type UserDatabase interface {
	Get(id string, opts ...UserDatabaseOption) (*User, error)
	GetAll() ([]*User, error)
	GetAllServiceAccount() ([]*User, error)
	GetAccessToken(value string) (*AccessToken, error)
	GetAccessTokens(id string) ([]*AccessToken, error)
	GetIdentityByLoginName(ctx context.Context, loginName string) (string, error)
	Set(ctx context.Context, user *User) error
	SetAccessToken(ctx context.Context, token *AccessToken) error
	Delete(ctx context.Context, id string) error
	SetState(ctx context.Context, unique string) (string, error)
	GetState(ctx context.Context, state string) (string, error)
	DeleteState(ctx context.Context, state string) error
}

type AccessToken struct {
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	UserId    string    `json:"user_id"`
	Issuer    string    `json:"issuer"`
	CreatedAt time.Time `json:"created_at"`
}

type SSHKeys struct {
	UserId string `json:"user_id"`
	Keys   string `json:"keys"`
}

type User struct {
	Id            string          `json:"id"`
	LoginName     string          `json:"login_name"`
	Roles         []string        `json:"roles"`
	MaintainRoles map[string]bool `json:"maintain_roles,omitempty"`
	Admin         bool            `json:"admin"`
	Type          string          `json:"type"`
	Comment       string          `json:"comment"`
	LastLogin     time.Time       `json:"last_login"`

	Version  int64 `json:"-"`
	RootUser bool  `json:"-"`
}

func (u *User) Setup() {
	if u.Roles == nil {
		u.Roles = make([]string, 0)
	}
	if u.MaintainRoles == nil {
		u.MaintainRoles = make(map[string]bool)
	}
}

func (u *User) ServiceAccount() bool {
	return u.Type == UserTypeServiceAccount
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
