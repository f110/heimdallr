package etcd

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"go.etcd.io/etcd/v3/clientv3"
)

func TestTapReadiness_IsReady(t *testing.T) {
	v := &TapReadiness{Watcher: NewTapWatcher(client), Lease: NewTapLease(client)}

	if !v.IsReady() {
		t.Fatal("Expect IsReady")
	}
}

func TestNewTapWatcher(t *testing.T) {
	v := NewTapWatcher(client)
	if v == nil {
		t.Fatal("NewTapWatcher should always return a value")
	}

	if !v.IsReady() {
		t.Error("Expect IsReady")
	}
}

func TestTapWatcher_Watch(t *testing.T) {
	v := NewTapWatcher(client)

	watchCh := v.Watch(context.Background(), "test")

	if !v.IsReady() {
		t.Error("Expect IsReady")
	}
	_, err := client.Put(context.Background(), "test", "")
	if err != nil {
		t.Fatal(err)
	}

	select {
	case e, ok := <-watchCh:
		if !ok {
			t.Fatal("Expect got a value but channel is closed")
		}
		if len(e.Events) != 1 {
			t.Errorf("Expect 1 event: %d event", len(e.Events))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout")
	}
}

func TestTapWatcher_Close(t *testing.T) {
	// Create a new connection to etcd.
	// because this test will be closed a connection.
	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{etcdUrl.String()},
		DialTimeout: 1 * time.Second,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed connect to etcd: %v\n", err)
		os.Exit(1)
	}

	v := NewTapWatcher(client)

	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	if v.IsReady() {
		t.Fatal("Expect is not ready")
	}
}

func TestNewTapLease(t *testing.T) {
	v := NewTapLease(client)
	if v == nil {
		t.Fatal("NewTapLease should always return a value")
	}

	if !v.IsReady() {
		t.Error("Expect IsReady")
	}
}

func TestTapLease_KeepAlive(t *testing.T) {
	v := NewTapLease(client)

	g, err := v.Grant(context.Background(), 60)
	if err != nil {
		t.Fatal(err)
	}
	keepAliveCh, err := v.KeepAlive(context.Background(), g.ID)
	if err != nil {
		t.Fatal(err)
	}

	if !v.IsReady() {
		t.Error("Expect IsReady")
	}

	select {
	case _, ok := <-keepAliveCh:
		if !ok {
			t.Fatal("Expect got a value but channel is closed")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout")
	}
}

func TestTapLease_Close(t *testing.T) {
	// Create a new connection to etcd.
	// because this test will be closed a connection.
	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{etcdUrl.String()},
		DialTimeout: 1 * time.Second,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed connect to etcd: %v\n", err)
		os.Exit(1)
	}

	v := NewTapLease(client)

	if err := v.Close(); err != nil {
		t.Fatal(err)
	}

	if v.IsReady() {
		t.Fatal("Expect is not ready")
	}
}
