package etcd

import (
	"context"
	"fmt"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.f110.dev/xerrors"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/netutil"
)

type ClusterDatabase struct {
	client *clientv3.Client

	id     string
	cancel context.CancelFunc
}

var _ database.ClusterDatabase = &ClusterDatabase{}

func NewClusterDatabase(_ context.Context, client *clientv3.Client) (*ClusterDatabase, error) {
	hostname, err := netutil.GetHostname()
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return &ClusterDatabase{client: client, id: hostname}, nil
}

func (d *ClusterDatabase) Id() string {
	return d.id
}

func (d *ClusterDatabase) Join(ctx context.Context) error {
	if d.cancel != nil {
		return xerrors.NewWithStack("etcd: already joined")
	}

	lease, err := d.client.Grant(ctx, 30)
	if err != nil {
		return xerrors.WithStack(err)
	}
	member := &database.Member{
		Id: d.id,
	}
	b, err := yaml.Marshal(member)
	if err != nil {
		return xerrors.WithStack(err)
	}

	_, err = d.client.Put(ctx, fmt.Sprintf("cluster/%s", d.Id()), string(b), clientv3.WithLease(lease.ID))
	if err != nil {
		return xerrors.WithStack(err)
	}
	kaCtx, cancelFunc := context.WithCancel(context.Background())
	go func() {
		defer func() {
			cancelFunc()
			d.cancel = nil
		}()

		resCh, err := d.client.KeepAlive(kaCtx, lease.ID)
		if err != nil {
			return
		}
	Loop:
		for {
			select {
			case _, ok := <-resCh:
				if ok {
					continue
				} else {
					break Loop
				}
			}
		}
	}()
	d.cancel = cancelFunc

	return nil
}

func (d *ClusterDatabase) Leave(ctx context.Context) error {
	_, err := d.client.Delete(ctx, fmt.Sprintf("cluster/%s", d.Id()))
	if err != nil {
		return xerrors.WithStack(err)
	}
	if d.cancel != nil {
		d.cancel()
		d.cancel = nil
	}

	return nil
}

func (d *ClusterDatabase) MemberList(ctx context.Context) ([]*database.Member, error) {
	res, err := d.client.Get(ctx, "cluster/", clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}

	members := make([]*database.Member, res.Count)
	for i, v := range res.Kvs {
		member := &database.Member{}
		if err := yaml.Unmarshal(v.Value, member); err != nil {
			return nil, xerrors.WithStack(err)
		}
		members[i] = member
	}
	return members, nil
}

func (d *ClusterDatabase) Alive() bool {
	if d.cancel == nil {
		return false
	}

	return true
}
