package etcd

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/etcd/clientv3"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/netutil"
	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"
)

type ClusterDatabase struct {
	client *clientv3.Client

	Id     string
	cancel context.CancelFunc
}

var _ database.ClusterDatabase = &ClusterDatabase{}

func NewClusterDatabase(ctx context.Context, client *clientv3.Client) (*ClusterDatabase, error) {
	hostname, err := netutil.GetHostname()
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	return &ClusterDatabase{client: client, Id: hostname}, nil
}

func (d *ClusterDatabase) Join(ctx context.Context) error {
	if d.cancel != nil {
		return errors.New("etcd: already joined")
	}

	lease, err := d.client.Grant(ctx, 30)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	member := &database.Member{
		Id: d.Id,
	}
	b, err := yaml.Marshal(member)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	_, err = d.client.Put(ctx, fmt.Sprintf("cluster/%s", d.Id), string(b), clientv3.WithLease(lease.ID))
	if err != nil {
		return xerrors.Errorf(": %v", err)
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
	_, err := d.client.Delete(ctx, fmt.Sprintf("cluster/%s", d.Id))
	if err != nil {
		return xerrors.Errorf(": %v", err)
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
			return nil, xerrors.Errorf(": %v", err)
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
