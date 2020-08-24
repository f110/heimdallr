package mysql

import (
	"context"
	"database/sql"

	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/database/mysql/dao"
	"go.f110.dev/heimdallr/pkg/database/mysql/entity"
	"go.f110.dev/heimdallr/pkg/netutil"
)

type ClusterDatabase struct {
	dao *dao.Repository
	id  string
}

func NewCluster(dao *dao.Repository) (*ClusterDatabase, error) {
	hostname, err := netutil.GetHostname()
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	return &ClusterDatabase{dao: dao, id: hostname}, nil
}

func (c *ClusterDatabase) Id() string {
	return c.id
}

func (c *ClusterDatabase) Join(ctx context.Context) error {
	_, err := c.dao.Node.Create(ctx, &entity.Node{Hostname: c.id})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (c *ClusterDatabase) Leave(ctx context.Context) error {
	n, err := c.dao.Node.ListHostname(ctx, c.id)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if len(n) != 1 {
		return sql.ErrNoRows
	}

	err = c.dao.Node.Delete(ctx, n[0].Id)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (c *ClusterDatabase) MemberList(ctx context.Context) ([]*database.Member, error) {
	nodes, err := c.dao.Node.ListAll(ctx)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	members := make([]*database.Member, len(nodes))
	for i, v := range nodes {
		members[i] = &database.Member{
			Id: v.Hostname,
		}
	}

	return members, nil
}

func (c *ClusterDatabase) Alive() bool {
	return true
}
