package database

import "golang.org/x/xerrors"

var (
	ErrUserNotFound = xerrors.New("database: user not found")
)

type User struct {
	Email string   `yaml:"email"`
	Roles []string `yaml:"roles"`
}
