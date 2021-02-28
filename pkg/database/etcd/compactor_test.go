package etcd

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewCompactor(t *testing.T) {
	c, err := NewCompactor(client)
	require.NoError(t, err)
	require.NotNil(t, c)

	finished := make(chan struct{})
	ctx, cancelFunc := context.WithCancel(context.Background())
	go func() {
		c.Start(ctx)
		close(finished)
	}()
	cancelFunc()

	select {
	case <-finished:
	case <-time.After(time.Second):
		require.Fail(t, "Timeout")
	}
}

func TestCompactor_Compaction(t *testing.T) {
	c, err := NewCompactor(client)
	require.NoError(t, err)

	err = c.compact()
	require.NoError(t, err)
}
