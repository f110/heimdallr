package database

import "context"

type ClusterDatabase interface {
	Id() string
	Join(ctx context.Context) error
	Leave(ctx context.Context) error
	MemberList(ctx context.Context) ([]*Member, error)
	Alive() bool
	Defragment(ctx context.Context) map[string]error
}

type Member struct {
	Id string `json:"id"`
}
