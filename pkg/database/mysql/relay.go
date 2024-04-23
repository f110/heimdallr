package mysql

import (
	"context"
	"sync"
	"time"

	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/database/mysql/dao"
	"go.f110.dev/heimdallr/pkg/database/mysql/entity"
)

type RelayLocator struct {
	dao *dao.Repository

	mu sync.Mutex
	ch []chan *database.Relay

	goneWatchOnce sync.Once
	lastRelay     []*entity.Relay
}

var _ database.RelayLocator = &RelayLocator{}

func NewRelayLocator(dao *dao.Repository) *RelayLocator {
	return &RelayLocator{dao: dao}
}

func (r *RelayLocator) Get(name string) (*database.Relay, bool) {
	relay, err := r.dao.Relay.ListName(context.TODO(), name)
	if err != nil {
		return nil, false
	}
	if len(relay) != 1 {
		return nil, false
	}

	v := relay[0]
	return &database.Relay{
		Name:        v.Name,
		Addr:        v.Addr,
		FromAddr:    v.FromAddr,
		ConnectedAt: v.ConnectedAt,
		UpdatedAt:   *v.UpdatedAt,
	}, true
}

func (r *RelayLocator) Set(ctx context.Context, relay *database.Relay) error {
	_, err := r.dao.Relay.Create(ctx, &entity.Relay{
		Name:        relay.Name,
		Addr:        relay.Addr,
		FromAddr:    relay.FromAddr,
		ConnectedAt: relay.ConnectedAt,
	})
	if err != nil {
		return xerrors.WithStack(err)
	}
	return nil
}

func (r *RelayLocator) Update(ctx context.Context, relay *database.Relay) error {
	v, err := r.dao.Relay.SelectEndpoint(ctx, relay.Name, relay.Addr)
	if err != nil {
		return xerrors.WithStack(err)
	}

	v.FromAddr = relay.FromAddr
	v.ConnectedAt = relay.ConnectedAt

	if err := r.dao.Relay.Update(ctx, v); err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func (r *RelayLocator) Delete(ctx context.Context, name, addr string) error {
	v, err := r.dao.Relay.SelectEndpoint(ctx, name, addr)
	if err != nil {
		return xerrors.WithStack(err)
	}

	err = r.dao.Relay.Delete(ctx, v.Id)
	if err != nil {
		return xerrors.WithStack(err)
	}
	return nil
}

func (r *RelayLocator) Gone() chan *database.Relay {
	ch := make(chan *database.Relay)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ch = append(r.ch, ch)

	r.goneWatchOnce.Do(func() {
		go r.watchGone()
	})

	return ch
}

func (r *RelayLocator) GetListenedAddrs() []string {
	relay, err := r.dao.Relay.ListAll(context.TODO())
	if err != nil {
		return nil
	}

	result := make([]string, len(relay))
	for i, v := range relay {
		result[i] = v.Addr
	}

	return result
}

func (r *RelayLocator) ListAllConnectedAgents() []*database.Relay {
	relay, err := r.dao.Relay.ListAll(context.TODO())
	if err != nil {
		return nil
	}

	result := make([]*database.Relay, len(relay))
	for i, v := range relay {
		result[i] = &database.Relay{
			Name:        v.Name,
			Addr:        v.Addr,
			FromAddr:    v.FromAddr,
			ConnectedAt: v.ConnectedAt,
			UpdatedAt:   *v.UpdatedAt,
		}
	}
	return result
}

func (r *RelayLocator) watchGone() {
	t := time.NewTicker(1 * time.Minute)

	for {
		select {
		case <-t.C:
			r.checkRelay()
		}
	}
}

func (r *RelayLocator) checkRelay() {
	ctx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelFunc()

	relay, err := r.dao.Relay.ListAll(ctx)
	if err != nil {
		return
	}

	m := make(map[int32]*entity.Relay)
	for _, v := range relay {
		m[v.Id] = v
	}

	deletedRelay := make([]*entity.Relay, 0)
	for _, v := range r.lastRelay {
		if _, ok := m[v.Id]; !ok {
			deletedRelay = append(deletedRelay, v)
		}
	}

	r.mu.Lock()
	for _, v := range deletedRelay {
		value := &database.Relay{
			Name:        v.Name,
			Addr:        v.Addr,
			FromAddr:    v.FromAddr,
			ConnectedAt: v.ConnectedAt,
			UpdatedAt:   *v.UpdatedAt,
		}

		for _, ch := range r.ch {
			select {
			case ch <- value:
			default:
			}
		}
	}
	r.mu.Unlock()
}
