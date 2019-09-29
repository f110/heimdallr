package etcd

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"
)

type RelayLocator struct {
	client *clientv3.Client
	gone   chan *database.Relay

	mu    sync.RWMutex
	cache map[string]*database.Relay
}

var _ database.RelayLocator = &RelayLocator{}

func NewRelayLocator(ctx context.Context, client *clientv3.Client) (*RelayLocator, error) {
	rl := &RelayLocator{client: client, cache: make(map[string]*database.Relay), gone: make(chan *database.Relay)}

	res, err := client.Get(ctx, "relay/", clientv3.WithPrefix())
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	for _, v := range res.Kvs {
		r := &database.Relay{}
		if err := yaml.Unmarshal(v.Value, r); err != nil {
			logger.Log.Warn("Ignore relay record due to unmarshal error", zap.Error(err), zap.String("key", string(v.Key)))
			continue
		}
		if r.Name == "" {
			logger.Log.Warn("Ignore relay caching", zap.String("key", string(v.Key)))
		}
		r.Version = v.Version
		rl.cache[r.Name] = r
	}
	w := client.Watch(ctx, "relay/", clientv3.WithPrefix(), clientv3.WithRev(res.Header.Revision))
	go rl.watch(w)

	return rl, nil
}

// TODO: Support multiple relay
func (l *RelayLocator) Get(name string) (*database.Relay, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	v, ok := l.cache[name]
	return v, ok
}

func (l *RelayLocator) Set(ctx context.Context, r *database.Relay) error {
	b, err := yaml.Marshal(r)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	_, err = l.client.Put(ctx, fmt.Sprintf("relay/%s/%s", r.Name, r.Addr), string(b))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

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

	return nil
}

func (l *RelayLocator) Gone() chan *database.Relay {
	return l.gone
}

func (l *RelayLocator) watch(watch clientv3.WatchChan) {
	for {
		select {
		case events := <-watch:
			for _, e := range events.Events {
				switch e.Type {
				case clientv3.EventTypePut:
					r := &database.Relay{}
					if err := yaml.Unmarshal(e.Kv.Value, r); err != nil {
						continue
					}
					r.Version = e.Kv.Version

					logger.Log.Debug("Add relay to cache", zap.String("name", r.Name))
					l.mu.Lock()
					l.cache[r.Name] = r
					l.mu.Unlock()
				case clientv3.EventTypeDelete:
					key := strings.Split(string(e.Kv.Key), "/")
					name := key[len(key)-2]
					if name == "" {
						continue
					}

					if _, ok := l.cache[name]; !ok {
						continue
					}
					logger.Log.Debug("Remove relay from cache", zap.String("name", name))
					l.mu.Lock()
					delete(l.cache, name)
					l.mu.Unlock()

					select {
					case l.gone <- &database.Relay{Name: key[len(key)-2], Addr: key[len(key)-1]}:
					default:
					}
				}
			}
		}
	}
}
