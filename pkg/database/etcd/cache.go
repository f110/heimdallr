package etcd

import (
	"bytes"
	"context"
	"errors"
	"sync"

	"go.etcd.io/etcd/v3/clientv3"
	"go.etcd.io/etcd/v3/mvcc/mvccpb"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
)

type Cache struct {
	client   *clientv3.Client
	prefix   string
	initData []*mvccpb.KeyValue
	notifies []chan struct{}
	cancel   context.CancelFunc

	mu    sync.RWMutex
	cache []*mvccpb.KeyValue

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
		return nil, database.ErrClosed
	}

	return c.cache, nil
}

func (c *Cache) Len() int {
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

func (c *Cache) Notify() chan struct{} {
	ch := make(chan struct{}, 1)
	c.notifies = append(c.notifies, ch)
	return ch
}

func (c *Cache) Start(ctx context.Context) {
	go func() {
		if err := c.watch(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Log.Warn("Close cache", zap.Error(err))
		}
	}()
}

func (c *Cache) Close() {
	if c.cancel != nil {
		c.cancel()
	}
}

func (c *Cache) Synced() (chan struct{}, error) {
	if c.cancel == nil {
		return c.synced, database.ErrClosed
	}
	return c.synced, nil
}

func (c *Cache) WaitForSync(ctx context.Context) error {
	synced, _ := c.Synced()

	select {
	case <-synced:
		if c.cancel == nil {
			return database.ErrClosed
		}
		return nil
	case <-ctx.Done():
		return xerrors.Errorf(": %w", ctx.Err())
	}
}

func (c *Cache) watch(ctx context.Context) error {
	if c.cancel != nil {
		logger.Log.Info("Already running watch channel. be going to close other")
		c.cancel()
	}

	wCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	defer func() {
		c.cancel = nil
	}()

	for {
		res, err := c.client.Get(wCtx, c.prefix, clientv3.WithPrefix())
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		c.mu.Lock()
		c.cache = append(c.initData, res.Kvs...)
		c.mu.Unlock()
		c.once.Do(func() {
			close(c.synced)
		})

		err = c.startWatch(wCtx, res.Header.Revision)
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil
		}
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}
}

func (c *Cache) startWatch(ctx context.Context, revision int64) error {
	logger.Log.Debug("Start watch", zap.String("prefix", c.prefix))
	watchCh := c.client.Watch(ctx, c.prefix, clientv3.WithPrefix(), clientv3.WithRev(revision))
	for {
		select {
		case res, ok := <-watchCh:
			if !ok {
				logger.Log.Debug("Watch channel was closed")
				return nil
			}

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
				case clientv3.EventTypeDelete:
					c.mu.Lock()
					for i, v := range c.cache {
						if bytes.Equal(v.Key, event.Kv.Key) {
							c.cache = append(c.cache[:i], c.cache[i+1:]...)
							break
						}
					}
					c.mu.Unlock()
				}
			}

			c.sendNotify()
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (c *Cache) sendNotify() {
	for _, v := range c.notifies {
		select {
		case v <- struct{}{}:
		default:
		}
	}
}
