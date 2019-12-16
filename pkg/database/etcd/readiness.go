package etcd

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/coreos/etcd/clientv3"
)

type TapReadiness struct {
	Watcher *TapWatcher
	Lease   *TapLease
}

func (r *TapReadiness) IsReady() bool {
	return r.Watcher.IsReady() == true && r.Lease.IsReady() == true
}

type TapWatcher struct {
	clientv3.Watcher

	wg       sync.WaitGroup
	stopC    chan struct{}
	stopOnce sync.Once

	errCount int32
}

var _ clientv3.Watcher = &TapWatcher{}

func NewTapWatcher(w clientv3.Watcher) *TapWatcher {
	return &TapWatcher{Watcher: w, stopC: make(chan struct{})}
}

func (p *TapWatcher) IsReady() bool {
	if p.errCount == 0 {
		return true
	}

	return false
}

func (p *TapWatcher) Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	wc := p.Watcher.Watch(ctx, key, opts...)

	res := make(chan clientv3.WatchResponse)
	p.wg.Add(1)
	go func() {
		defer func() {
			close(res)
			if ctx.Err() == nil {
				atomic.AddInt32(&p.errCount, 1)
			}
			p.wg.Done()
		}()

		for wr := range wc {
			select {
			case res <- wr:
			case <-ctx.Done():
				return
			case <-p.stopC:
			}
		}
	}()

	return res
}

func (p *TapWatcher) Close() error {
	atomic.AddInt32(&p.errCount, 1)
	err := p.Watcher.Close()
	p.stopOnce.Do(func() {
		close(p.stopC)
	})
	p.wg.Wait()
	return err
}

type TapLease struct {
	clientv3.Lease

	wg       sync.WaitGroup
	stopC    chan struct{}
	stopOnce sync.Once

	errCount int32
}

var _ clientv3.Lease = &TapLease{}

func NewTapLease(l clientv3.Lease) *TapLease {
	return &TapLease{Lease: l, stopC: make(chan struct{})}
}

func (l *TapLease) IsReady() bool {
	if l.errCount == 0 {
		return true
	}

	return false
}

func (l *TapLease) KeepAlive(ctx context.Context, id clientv3.LeaseID) (<-chan *clientv3.LeaseKeepAliveResponse, error) {
	rc, err := l.Lease.KeepAlive(ctx, id)
	if err != nil {
		return nil, err
	}

	res := make(chan *clientv3.LeaseKeepAliveResponse)
	l.wg.Add(1)
	go func() {
		defer func() {
			close(res)
			if ctx.Err() == nil {
				atomic.AddInt32(&l.errCount, 1)
			}
			l.wg.Done()
		}()

		for kar := range rc {
			select {
			case res <- kar:
			case <-ctx.Done():
			case <-l.stopC:
				return
			}
		}
	}()

	return res, nil
}

func (l *TapLease) Close() error {
	atomic.AddInt32(&l.errCount, 1)
	err := l.Lease.Close()
	l.stopOnce.Do(func() {
		close(l.stopC)
	})
	l.wg.Wait()
	return err
}
