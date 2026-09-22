package etcd

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"

	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
)

type Cache struct {
	client   *clientv3.Client
	prefix   string
	initData []*mvccpb.KeyValue

	mu       sync.RWMutex
	cache    []*mvccpb.KeyValue
	notifies []chan struct{}
	cancel   context.CancelFunc

	once   *sync.Once
	synced chan struct{}
}

func NewCache(client *clientv3.Client, keyPrefix string, initData []*mvccpb.KeyValue) *Cache {
	return &Cache{
		client:   client,
		prefix:   keyPrefix,
		initData: initData,
		once:     &sync.Once{},
		synced:   make(chan struct{}),
	}
}

func (c *Cache) All() ([]*mvccpb.KeyValue, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cancel == nil {
		return nil, xerrors.WithStack(database.ErrClosed)
	}

	return c.cache, nil
}

func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.cache)
}

func (c *Cache) Get(key []byte) *mvccpb.KeyValue {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, v := range c.cache {
		if bytes.Equal(v.Key, key) {
			return v
		}
	}

	return nil
}

// Notify returns a channel that receives a value each time the cache has been
// changed by the watch. The change is already visible through Get and All when
// the value is sent.
func (c *Cache) Notify() chan struct{} {
	ch := make(chan struct{}, 1)

	c.mu.Lock()
	c.notifies = append(c.notifies, ch)
	c.mu.Unlock()

	return ch
}

func (c *Cache) Start(ctx context.Context) {
	go func() {
		if err := c.watch(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Log.Warn("Close cache", slog.Any("error", err))
		}
	}()
}

func (c *Cache) Close() {
	c.mu.RLock()
	cancel := c.cancel
	c.mu.RUnlock()

	if cancel != nil {
		cancel()
	}
}

func (c *Cache) Synced() (chan struct{}, error) {
	if c.closed() {
		return c.synced, database.ErrClosed
	}
	return c.synced, nil
}

func (c *Cache) WaitForSync(ctx context.Context) error {
	synced, _ := c.Synced()

	select {
	case <-synced:
		if c.closed() {
			return database.ErrClosed
		}
		return nil
	case <-ctx.Done():
		return xerrors.WithStack(ctx.Err())
	}
}

// closed returns true when the watch channel is not running.
func (c *Cache) closed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.cancel == nil
}

func (c *Cache) watch(ctx context.Context) error {
	wCtx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	if c.cancel != nil {
		logger.Log.Info("Already running watch channel. be going to close other")
		c.cancel()
	}
	c.cancel = cancel
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.cancel = nil
		c.mu.Unlock()
	}()

	for {
		res, err := c.client.Get(wCtx, c.prefix, clientv3.WithPrefix())
		if err != nil {
			return xerrors.WithStack(err)
		}
		c.mu.Lock()
		c.cache = append(c.initData, res.Kvs...)
		c.mu.Unlock()
		c.once.Do(func() {
			close(c.synced)
		})

		err = c.startWatch(wCtx, res.Header.Revision+1)
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (c *Cache) startWatch(ctx context.Context, revision int64) error {
	logger.Log.Debug("Start watch", slog.String("prefix", c.prefix))
	watchCh := c.client.Watch(ctx, c.prefix, clientv3.WithPrefix(), clientv3.WithRev(revision))
	for {
		select {
		case res, ok := <-watchCh:
			if !ok {
				logger.Log.Debug("Watch channel was closed")
				return nil
			}

			applied := 0
			for _, event := range res.Events {
				switch event.Type {
				case clientv3.EventTypePut:
					c.mu.Lock()
					found := false
					for i, v := range c.cache {
						if bytes.Equal(v.Key, event.Kv.Key) {
							found = true
							c.cache[i] = event.Kv
							break
						}
					}
					if !found {
						c.cache = append(c.cache, event.Kv)
					}
					c.mu.Unlock()
					applied++
				case clientv3.EventTypeDelete:
					c.mu.Lock()
					for i, v := range c.cache {
						if bytes.Equal(v.Key, event.Kv.Key) {
							c.cache = append(c.cache[:i], c.cache[i+1:]...)
							applied++
							break
						}
					}
					c.mu.Unlock()
				}
			}

			if applied > 0 {
				c.sendNotify()
			}
		case <-ctx.Done():
			return xerrors.WithStack(ctx.Err())
		}
	}
}

func (c *Cache) sendNotify() {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, v := range c.notifies {
		select {
		case v <- struct{}{}:
		default:
		}
	}
}
