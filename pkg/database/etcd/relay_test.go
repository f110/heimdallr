package etcd

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.f110.dev/heimdallr/pkg/database"
)

func TestRelayLocator(t *testing.T) {
	t.Run("New", func(t *testing.T) {
		rl, err := NewRelayLocator(context.Background(), client)
		require.NoError(t, err)
		require.NotNil(t, rl)
	})

	t.Run("GetAndSet", func(t *testing.T) {
		rl, err := NewRelayLocator(context.Background(), client)
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		err = rl.cache.WaitForSync(ctx)
		require.NoError(t, err)

		notify := rl.cache.Notify()

		err = rl.Set(context.Background(), &database.Relay{Name: t.Name(), Addr: "127.0.0.1:10000"})
		require.NoError(t, err)
		waitNotify(t, notify)

		relay, ok := rl.Get(t.Name())
		require.True(t, ok)
		assert.Equal(t, "127.0.0.1:10000", relay.Addr)

		addrs := rl.GetListenedAddrs()
		assert.Len(t, addrs, 1)

		relays := rl.ListAllConnectedAgents()
		assert.Len(t, relays, 1)

		err = rl.Delete(context.Background(), t.Name(), "127.0.0.1:10000")
		require.NoError(t, err)
		waitNotify(t, notify)

		_, ok = rl.Get(t.Name())
		require.False(t, ok)
	})

	t.Run("Update", func(t *testing.T) {
		rl, err := NewRelayLocator(context.Background(), client)
		require.NoError(t, err)
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		err = rl.cache.WaitForSync(ctx)
		require.NoError(t, err)

		notify := rl.cache.Notify()

		updatedAt := time.Now().Add(-10 * time.Second)
		r := &database.Relay{Name: t.Name(), Addr: "127.0.0.1:10000", UpdatedAt: updatedAt}
		err = rl.Set(context.Background(), r)
		require.NoError(t, err)
		waitNotify(t, notify)

		relay, ok := rl.Get(t.Name())
		require.True(t, ok)

		err = rl.Update(context.Background(), relay)
		require.NoError(t, err)
		require.NotEqual(t, updatedAt.Unix(), relay.UpdatedAt.Unix())
	})
}
