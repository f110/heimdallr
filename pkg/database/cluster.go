package database

import "context"

type ClusterDatabase interface {
	Join(ctx context.Context) error
	Leave(ctx context.Context) error
	MemberList(ctx context.Context) ([]*Member, error)
}

type Member struct {
	Id string `json:"id"`
}
