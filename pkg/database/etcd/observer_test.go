package etcd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

func TestWatchStreamObserver(t *testing.T) {
	t.Run("Watch", func(t *testing.T) {
		o := NewWatchStreamObserver()
		ch := o.Subscribe()

		openStream(t, o, watchStreamMethod)
		assert.Len(t, ch, 1)
	})

	t.Run("OtherMethod", func(t *testing.T) {
		o := NewWatchStreamObserver()
		ch := o.Subscribe()

		openStream(t, o, "/etcdserverpb.Lease/LeaseKeepAlive")
		assert.Len(t, ch, 0)
	})

	t.Run("Unsubscribe", func(t *testing.T) {
		o := NewWatchStreamObserver()
		ch := o.Subscribe()
		o.Unsubscribe(ch)

		openStream(t, o, watchStreamMethod)
		assert.Len(t, ch, 0)
	})
}

func openStream(t *testing.T, o *WatchStreamObserver, method string) {
	t.Helper()

	streamer := func(_ context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn, _ string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
		return nil, nil
	}
	_, err := o.StreamInterceptor()(context.Background(), &grpc.StreamDesc{}, nil, method, streamer)
	assert.NoError(t, err)
}
