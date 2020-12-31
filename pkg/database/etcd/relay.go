package etcd

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.etcd.io/etcd/v3/clientv3"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
)

type RelayLocator struct {
	client      *clientv3.Client
	gone        chan *database.Relay
	watchCancel context.CancelFunc

	mu    sync.RWMutex
	cache map[string]*database.Relay

	myListenedAddr []string
}

var _ database.RelayLocator = &RelayLocator{}

func NewRelayLocator(ctx context.Context, client *clientv3.Client) (*RelayLocator, error) {
	watchCtx, cancel := context.WithCancel(context.Background())
	rl := &RelayLocator{
		client:         client,
		watchCancel:    cancel,
		cache:          make(map[string]*database.Relay),
		gone:           make(chan *database.Relay),
		myListenedAddr: make([]string, 0),
	}

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

	w := client.Watch(watchCtx, "relay/", clientv3.WithPrefix(), clientv3.WithRev(res.Header.Revision))
	go rl.watch(w, res.Header.Revision)

	return rl, nil
}

func (l *RelayLocator) Get(name string) (*database.Relay, bool) {
	// TODO: Support multiple relay
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
	l.cache[r.Name] = r
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
	delete(l.cache, name)
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
	l.mu.Lock()
	defer l.mu.Unlock()

	result := make([]*database.Relay, 0, len(l.cache))
	for _, v := range l.cache {
		result = append(result, v)
	}

	return result
}

func (l *RelayLocator) watch(watch clientv3.WatchChan, startRev int64) {
	logger.Log.Debug("Start watch relay locator")
	defer logger.Log.Debug("Stop watch relay locator")

	for {
		select {
		case events := <-watch:
			if len(events.Events) == 0 {
				return
			}
			if startRev >= events.Header.Revision {
				continue
			}

			l.watchEvents(events.Events)
		}
	}
}

func (l *RelayLocator) watchEvents(events []*clientv3.Event) {
	for _, e := range events {
		switch e.Type {
		case clientv3.EventTypePut:
			r := &database.Relay{}
			if err := yaml.Unmarshal(e.Kv.Value, r); err != nil {
				continue
			}
			r.Version = e.Kv.Version

			logger.Log.Debug("Add a relay to cache", zap.String("name", r.Name))
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
				logger.Log.Debug("RelayLocator: gone channel is blocking")
			}
		}
	}
}

func (l *RelayLocator) Close() {
	l.watchCancel()
}
