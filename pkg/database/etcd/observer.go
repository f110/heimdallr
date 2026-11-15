package etcd

import (
	"context"
	"sync"

	"google.golang.org/grpc"
)

const watchStreamMethod = "/etcdserverpb.Watch/Watch"

// WatchStreamObserver notifies the subscribers each time a gRPC stream for the watch is opened.
// clientv3 reopens the stream internally when the connection to etcd is lost,
// and the subscribers can find it out through WatchStreamObserver.
type WatchStreamObserver struct {
	mu   sync.Mutex
	subs []chan struct{}
}

func NewWatchStreamObserver() *WatchStreamObserver {
	return &WatchStreamObserver{}
}

// StreamInterceptor returns the interceptor that has to be installed to the client by grpc.WithChainStreamInterceptor.
func (o *WatchStreamObserver) StreamInterceptor() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		s, err := streamer(ctx, desc, cc, method, opts...)
		if err == nil && method == watchStreamMethod {
			o.notify()
		}
		return s, err
	}
}

// Subscribe returns a channel that receives a value each time a stream for the watch is opened.
func (o *WatchStreamObserver) Subscribe() chan struct{} {
	ch := make(chan struct{}, 1)

	o.mu.Lock()
	o.subs = append(o.subs, ch)
	o.mu.Unlock()

	return ch
}

// Unsubscribe unregisters the channel that Subscribe returned.
func (o *WatchStreamObserver) Unsubscribe(ch chan struct{}) {
	o.mu.Lock()
	defer o.mu.Unlock()

	for i, v := range o.subs {
		if v == ch {
			o.subs = append(o.subs[:i], o.subs[i+1:]...)
			break
		}
	}
}

func (o *WatchStreamObserver) notify() {
	o.mu.Lock()
	defer o.mu.Unlock()

	for _, v := range o.subs {
		select {
		case v <- struct{}{}:
		default:
		}
	}
}
