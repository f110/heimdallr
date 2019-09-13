package database

import (
	"golang.org/x/xerrors"
)

var (
	ErrUserNotFound = xerrors.New("database: user not found")
)

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
