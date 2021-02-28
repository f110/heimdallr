package etcd

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/v3/clientv3"
	"go.etcd.io/etcd/v3/mvcc/mvccpb"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/pkg/database"
)

func TestNewRelayLocator(t *testing.T) {
	rl, err := NewRelayLocator(context.Background(), client)
	require.NoError(t, err)
	require.NotNil(t, rl)
}

func TestRelayLocator_GetAndSet(t *testing.T) {
	rl, err := NewRelayLocator(context.Background(), client)
	require.NoError(t, err)

	err = rl.Set(context.Background(), &database.Relay{Name: t.Name(), Addr: "127.0.0.1:10000"})
	require.NoError(t, err)

	relay, ok := rl.Get(t.Name())
	require.True(t, ok)
	assert.Equal(t, "127.0.0.1:10000", relay.Addr)

	addrs := rl.GetListenedAddrs()
	assert.Len(t, addrs, 1)

	relays := rl.ListAllConnectedAgents()
	assert.Len(t, relays, 1)

	err = rl.Delete(context.Background(), t.Name(), "127.0.0.1:10000")
	require.NoError(t, err)

	_, ok = rl.Get(t.Name())
	require.False(t, ok)
}

func TestRelayLocator_Update(t *testing.T) {
	rl, err := NewRelayLocator(context.Background(), client)
	require.NoError(t, err)

	updatedAt := time.Now().Add(-10 * time.Second)
	r := &database.Relay{Name: t.Name(), Addr: "127.0.0.1:10000", UpdatedAt: updatedAt}
	err = rl.Set(context.Background(), r)
	require.NoError(t, err)
	relay, ok := rl.Get(t.Name())
	require.True(t, ok)

	err = rl.Update(context.Background(), relay)
	require.NoError(t, err)
	require.NotEqual(t, updatedAt.Unix(), relay.UpdatedAt.Unix())
}

func TestRelayLocator_Watch(t *testing.T) {
	rl, err := NewRelayLocator(context.Background(), client)
	require.NoError(t, err)

	started := make(chan struct{})
	gotCh := make(chan *database.Relay)
	goneCh := rl.Gone()
	go func() {
		close(started)
		gone := <-goneCh
		t.Logf("Got: %v", *gone)
		gotCh <- gone
	}()

	// Wait for starting goroutine
	select {
	case <-started:
	}

	buf, err := yaml.Marshal(&database.Relay{Name: t.Name()})
	require.NoError(t, err)
	rl.watchEvents([]*clientv3.Event{
		{
			Type: clientv3.EventTypePut,
			Kv:   &mvccpb.KeyValue{Value: buf},
		},
	})
	relay, ok := rl.Get(t.Name())
	assert.True(t, ok)
	assert.Equal(t, t.Name(), relay.Name)

	rl.watchEvents([]*clientv3.Event{
		{
			Type: clientv3.EventTypeDelete,
			Kv:   &mvccpb.KeyValue{Key: []byte("/" + t.Name() + "/127.0.0.1:10000")},
		},
	})
	_, ok = rl.Get(t.Name())
	assert.False(t, ok)

	select {
	case got := <-gotCh:
		assert.Equal(t, t.Name(), got.Name)
	case <-time.After(10 * time.Second):
		require.Fail(t, "Timeout")
	}
}
