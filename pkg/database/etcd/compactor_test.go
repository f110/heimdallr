package etcd

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	clientv3 "go.etcd.io/etcd/client/v3"
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

func TestCompactor_ContinueAfterError(t *testing.T) {
	cl, err := clientv3.New(clientv3.Config{Endpoints: []string{etcdUrl.String()}, DialTimeout: time.Second})
	require.NoError(t, err)
	c, err := NewCompactor(cl)
	require.NoError(t, err)
	require.NoError(t, cl.Close())

	origInterval := compactionInterval
	compactionInterval = 10 * time.Millisecond
	t.Cleanup(func() { compactionInterval = origInterval })

	finished := make(chan struct{})
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	go func() {
		c.Start(ctx)
		close(finished)
	}()

	select {
	case <-finished:
		require.Fail(t, "Compactor stopped due to the error")
	case <-time.After(5 * time.Second):
	}
}
