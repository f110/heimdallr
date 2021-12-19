package etcd

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestCache(t *testing.T) {
	t.Run("Put", func(t *testing.T) {
		t.Parallel()

		watchCh := make(chan clientv3.WatchResponse)
		cache := newCache(t, &fakeKV{}, &fakeWatcher{ch: watchCh})

		notify := cache.Notify()

		// Added new item
		watchCh <- clientv3.WatchResponse{
			Events: []*clientv3.Event{
				{
					Type: clientv3.EventTypePut,
					Kv: &mvccpb.KeyValue{
						Version: 1,
						Key:     []byte("test/ok"),
						Value:   []byte("foobar"),
					},
				},
			},
		}
		waitNotify(t, notify)

		kv := cache.Get([]byte("test/ok"))
		require.NotNil(t, kv)
		assert.Equal(t, []byte("test/ok"), kv.Key)
		assert.Equal(t, []byte("foobar"), kv.Value)

		kv = cache.Get([]byte("test/unknown"))
		assert.Nil(t, kv)

		// Update existing item
		watchCh <- clientv3.WatchResponse{
			Events: []*clientv3.Event{
				{
					Type: clientv3.EventTypePut,
					Kv: &mvccpb.KeyValue{
						Version: 2,
						Key:     []byte("test/ok"),
						Value:   []byte("baz"),
					},
					PrevKv: &mvccpb.KeyValue{
						Version: 1,
						Key:     []byte("test/ok"),
						Value:   []byte("foobar"),
					},
				},
			},
		}
		sendEvent(watchCh, clientv3.EventTypePut, &mvccpb.KeyValue{
			Version: 2,
			Key:     []byte("test/ok"),
			Value:   []byte("baz"),
		}, &mvccpb.KeyValue{
			Version: 1,
			Key:     []byte("test/ok"),
			Value:   []byte("foobar"),
		})
		waitNotify(t, notify)

		kv = cache.Get([]byte("test/ok"))
		require.NotNil(t, kv)
		assert.Equal(t, []byte("baz"), kv.Value)
		all, err := cache.All()
		require.NoError(t, err)
		require.Len(t, all, 2)
	})

	t.Run("Delete", func(t *testing.T) {
		t.Parallel()

		watchCh := make(chan clientv3.WatchResponse)
		cache := newCache(
			t,
			&fakeKV{kvs: []*mvccpb.KeyValue{
				{
					Version: 1,
					Key:     []byte("test/ok"),
					Value:   []byte("foobar"),
				},
			}},
			&fakeWatcher{ch: watchCh},
		)

		notify := cache.Notify()

		// Delete item
		sendEvent(watchCh, clientv3.EventTypeDelete, &mvccpb.KeyValue{
			Key: []byte("test/ok"),
		}, nil)
		waitNotify(t, notify)

		kv := cache.Get([]byte("test/ok"))
		assert.Nil(t, kv)
		all, err := cache.All()
		require.NoError(t, err)
		require.Len(t, all, 1)
	})

	t.Run("Reconnect", func(t *testing.T) {
		t.Parallel()

		watchCh := make(chan clientv3.WatchResponse)
		watcher := &fakeWatcher{ch: watchCh}
		kv := &fakeKV{}
		cache := newCache(t, kv, watcher)

		notify := cache.Notify()

		sendEvent(watchCh, clientv3.EventTypePut, &mvccpb.KeyValue{
			Version: 1,
			Key:     []byte("test/ok"),
			Value:   []byte("foobar"),
		}, nil)
		kv.kvs = append(kv.kvs, &mvccpb.KeyValue{
			Version: 1,
			Key:     []byte("test/ok"),
			Value:   []byte("foobar"),
		})
		waitNotify(t, notify)

		oldWatchCh := watchCh
		watchCh = make(chan clientv3.WatchResponse)
		watcher.ch = watchCh
		close(oldWatchCh)

		// Added new item
		sendEvent(watchCh, clientv3.EventTypePut, &mvccpb.KeyValue{
			Version: 1,
			Key:     []byte("test/new"),
			Value:   []byte("foobar"),
		}, nil)
		waitNotify(t, notify)

		all, err := cache.All()
		require.NoError(t, err)
		require.Len(t, all, 2)
	})

	t.Run("Close", func(t *testing.T) {
		t.Parallel()

		watchCh := make(chan clientv3.WatchResponse)
		cache := newCache(t, &fakeKV{}, &fakeWatcher{ch: watchCh})

		cache.Close()
	})
}

func newCache(t *testing.T, fakeKV *fakeKV, fakeWatcher *fakeWatcher) *Cache {
	c := &clientv3.Client{
		KV:      fakeKV,
		Watcher: fakeWatcher,
	}
	cache := NewCache(c, "test/", nil)
	cache.Start(context.Background())

	notify := cache.Notify()
	fakeWatcher.ch <- clientv3.WatchResponse{
		Events: []*clientv3.Event{
			{
				Type: clientv3.EventTypePut,
				Kv: &mvccpb.KeyValue{
					Version: 1,
					Key:     []byte("test/readiness"),
					Value:   []byte("foobar"),
				},
			},
		},
	}
	waitNotify(t, notify)

	return cache
}

func waitNotify(t *testing.T, ch chan struct{}) {
	t.Helper()

	select {
	case <-ch:
	case <-time.After(200 * time.Millisecond):
		require.Fail(t, "timed out")
	}
}

func sendEvent(ch chan clientv3.WatchResponse, typ mvccpb.Event_EventType, kv, prev *mvccpb.KeyValue) {
	ch <- clientv3.WatchResponse{
		Events: []*clientv3.Event{
			{
				Type:   typ,
				Kv:     kv,
				PrevKv: prev,
			},
		},
	}
}

type fakeKV struct {
	kvs []*mvccpb.KeyValue
}

func (f *fakeKV) Put(_ context.Context, _, _ string, _ ...clientv3.OpOption) (*clientv3.PutResponse, error) {
	panic("implement me")
}

func (f *fakeKV) Get(_ context.Context, _ string, _ ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	return &clientv3.GetResponse{
		Header: &etcdserverpb.ResponseHeader{
			Revision: 2,
		},
		Kvs: f.kvs,
	}, nil
}

func (f *fakeKV) Delete(_ context.Context, _ string, _ ...clientv3.OpOption) (*clientv3.DeleteResponse, error) {
	panic("implement me")
}

func (f *fakeKV) Compact(_ context.Context, _ int64, _ ...clientv3.CompactOption) (*clientv3.CompactResponse, error) {
	panic("implement me")
}

func (f *fakeKV) Do(_ context.Context, _ clientv3.Op) (clientv3.OpResponse, error) {
	panic("implement me")
}

func (f *fakeKV) Txn(_ context.Context) clientv3.Txn {
	panic("implement me")
}

type fakeWatcher struct {
	ch chan clientv3.WatchResponse
}

func (f *fakeWatcher) Watch(_ context.Context, _ string, _ ...clientv3.OpOption) clientv3.WatchChan {
	return f.ch
}

func (f *fakeWatcher) RequestProgress(_ context.Context) error {
	panic("implement me")
}

func (f *fakeWatcher) Close() error {
	panic("implement me")
}
