package memory

import (
	"context"
	"sync"

	"github.com/f110/lagrangian-proxy/pkg/database"
)

type ClusterDatabase struct {
	mu sync.Mutex
}

var _ database.ClusterDatabase = &ClusterDatabase{}

func NewClusterDatabase() *ClusterDatabase {
	return &ClusterDatabase{}
}

func (d *ClusterDatabase) Join(ctx context.Context) error {
	panic("implement me")
}

func (d *ClusterDatabase) Leave(ctx context.Context) error {
	panic("implement me")
}

func (d *ClusterDatabase) MemberList(ctx context.Context) ([]*database.Member, error) {
	panic("implement me")
}
