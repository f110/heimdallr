package etcd

import (
	"context"
	"testing"
	"time"
)

func TestNewCompactor(t *testing.T) {
	c, err := NewCompactor(client)
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("NewCompactor should return a value")
	}

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
		t.Fatal("Timeout")
	}
}

func TestCompactor_Compaction(t *testing.T) {
	c, err := NewCompactor(client)
	if err != nil {
		t.Fatal(err)
	}

	if err := c.compact(); err != nil {
		t.Fatal(err)
	}
}
