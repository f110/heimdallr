package memory

import (
	"context"
	"sync"

	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/netutil"
)

type ClusterDatabase struct {
	mu sync.Mutex

	id      string
	members map[string]struct{}
}

var _ database.ClusterDatabase = &ClusterDatabase{}

func NewClusterDatabase() *ClusterDatabase {
	hostname, err := netutil.GetHostname()
	if err != nil {
		hostname = "localhost"
	}

	return &ClusterDatabase{id: hostname, members: make(map[string]struct{})}
}

func (d *ClusterDatabase) Id() string {
	return d.id
}

func (d *ClusterDatabase) Join(_ context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.members[d.id] = struct{}{}
	return nil
}

func (d *ClusterDatabase) Leave(_ context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.members, d.id)
	return nil
}

func (d *ClusterDatabase) MemberList(ctx context.Context) ([]*database.Member, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	result := make([]*database.Member, 0)
	for k := range d.members {
		result = append(result, &database.Member{Id: k})
	}

	return result, nil
}

func (d *ClusterDatabase) Alive() bool {
	return true
}

func (d *ClusterDatabase) Defragment(_ context.Context) map[string]error {
	return map[string]error{d.id: nil}
}
