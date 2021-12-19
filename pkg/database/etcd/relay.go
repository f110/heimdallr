package etcd

import (
	"context"
	"fmt"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
)

type RelayLocator struct {
	client *clientv3.Client
	gone   chan *database.Relay
	cache  *Cache

	mu             sync.RWMutex
	myListenedAddr []string
}

var _ database.RelayLocator = &RelayLocator{}

func NewRelayLocator(_ context.Context, client *clientv3.Client) (*RelayLocator, error) {
	rl := &RelayLocator{
		client:         client,
		cache:          NewCache(client, "relay/", nil),
		gone:           make(chan *database.Relay),
		myListenedAddr: make([]string, 0),
	}
	rl.cache.Start(context.Background())

	return rl, nil
}

func (l *RelayLocator) Get(name string) (*database.Relay, bool) {
	// TODO: Support multiple relay
	all, err := l.cache.All()
	if err != nil {
		return nil, false
	}

	for _, v := range all {
		r := &database.Relay{}
		if err := yaml.Unmarshal(v.Value, r); err != nil {
			logger.Log.Warn("Ignore relay record due to unmarshal error", zap.Error(err), zap.String("key", string(v.Key)))
			continue
		}
		r.Version = v.Version

		if r.Name == name {
			return r, true
		}
	}

	return nil, false
}

func (l *RelayLocator) Set(ctx context.Context, r *database.Relay) error {
	b, err := yaml.Marshal(r)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	putRes, err := l.client.Put(ctx, fmt.Sprintf("relay/%s/%s", r.Name, r.Addr), string(b))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if putRes.PrevKv == nil {
		r.Version = 1
	} else {
		r.Version = putRes.PrevKv.Version + 1
	}

	l.mu.Lock()
	l.myListenedAddr = append(l.myListenedAddr, r.Addr)
	l.mu.Unlock()

	return nil
}

func (l *RelayLocator) Update(ctx context.Context, relay *database.Relay) error {
	relay.UpdatedAt = time.Now()
	b, err := yaml.Marshal(relay)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	key := fmt.Sprintf("relay/%s/%s", relay.Name, relay.Addr)
	txnRes, err := l.client.Txn(ctx).
		If(clientv3.Compare(clientv3.Version(key), "=", relay.Version)).
		Then(clientv3.OpPut(key, string(b))).
		Commit()
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if !txnRes.Succeeded {
		return xerrors.New("database: failure update relay record")
	}

	return nil
}

func (l *RelayLocator) Delete(ctx context.Context, name, addr string) error {
	_, err := l.client.Delete(ctx, fmt.Sprintf("relay/%s/%s", name, addr))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	l.mu.Lock()
	for i, v := range l.myListenedAddr {
		if v == addr {
			l.myListenedAddr = append(l.myListenedAddr[:i], l.myListenedAddr[i+1:]...)
		}
	}
	l.mu.Unlock()

	return nil
}

func (l *RelayLocator) Gone() chan *database.Relay {
	return l.gone
}

func (l *RelayLocator) GetListenedAddrs() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return l.myListenedAddr
}

func (l *RelayLocator) ListAllConnectedAgents() []*database.Relay {
	result := make([]*database.Relay, 0, l.cache.Len())
	all, err := l.cache.All()
	if err != nil {
		return nil
	}
	for _, v := range all {
		r := &database.Relay{}
		if err := yaml.Unmarshal(v.Value, r); err != nil {
			logger.Log.Warn("Ignore relay record due to unmarshal error", zap.Error(err), zap.String("key", string(v.Key)))
			continue
		}
		r.Version = v.Version
		result = append(result, r)
	}

	return result
}

func (l *RelayLocator) Close() {
	l.cache.Close()
}
