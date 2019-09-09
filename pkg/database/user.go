package database

import "golang.org/x/xerrors"

var (
	ErrUserNotFound = xerrors.New("database: user not found")
)

type User struct {
	Id    string   `yaml:"id"`
	Roles []string `yaml:"roles"`
}
