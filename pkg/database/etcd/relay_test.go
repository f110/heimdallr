package etcd

import (
	"context"
	"testing"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/mvcc/mvccpb"
	"sigs.k8s.io/yaml"

	"github.com/f110/lagrangian-proxy/pkg/database"
)

func TestNewRelayLocator(t *testing.T) {
	rl, err := NewRelayLocator(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if rl == nil {
		t.Fatal("NewRelayLocator should return a value")
	}
}

func TestRelayLocator_GetAndSet(t *testing.T) {
	rl, err := NewRelayLocator(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	defer clearDatabase(t)

	err = rl.Set(context.Background(), &database.Relay{Name: "test", Addr: "127.0.0.1:10000"})
	if err != nil {
		t.Fatal(err)
	}

	relay, ok := rl.Get("test")
	if !ok {
		t.Fatal("should return ok")
	}
	if relay.Addr != "127.0.0.1:10000" {
		t.Errorf("Unexpected addr: %s", relay.Addr)
	}

	addrs := rl.GetListenedAddrs()
	if len(addrs) != 1 {
		t.Errorf("Expect 1 addr: %d addrs", len(addrs))
	}

	relays := rl.ListAllConnectedAgents()
	if len(relays) != 1 {
		t.Errorf("Expect 1 connected agent: %d connected agents", len(relays))
	}

	err = rl.Delete(context.Background(), "test", "127.0.0.1:10000")
	if err != nil {
		t.Fatal(err)
	}

	_, ok = rl.Get("test")
	if ok {
		t.Fatal("should return not ok")
	}
}

func TestRelayLocator_Update(t *testing.T) {
	rl, err := NewRelayLocator(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}

	updatedAt := time.Now().Add(-10 * time.Second)
	r := &database.Relay{Name: "test", Addr: "127.0.0.1:10000", UpdatedAt: updatedAt}
	err = rl.Set(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	relay, ok := rl.Get("test")
	if !ok {
		t.Fatal("should return ok")
	}

	err = rl.Update(context.Background(), relay)
	if err != nil {
		t.Fatal(err)
	}
	if relay.UpdatedAt.Unix() == updatedAt.Unix() {
		t.Error("Should update UpdatedAt")
	}
}

func TestRelayLocator_Watch(t *testing.T) {
	rl, err := NewRelayLocator(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}

	gotCh := make(chan *database.Relay)
	goneCh := rl.Gone()
	go func() {
		gone := <-goneCh
		gotCh <- gone
	}()

	buf, err := yaml.Marshal(&database.Relay{Name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	rl.watchEvents([]*clientv3.Event{
		{
			Type: clientv3.EventTypePut,
			Kv:   &mvccpb.KeyValue{Value: buf},
		},
	})
	relay, ok := rl.Get("test")
	if !ok {
		t.Error("Expect return ok")
	}
	if relay.Name != "test" {
		t.Error("Expect Name is test")
	}

	rl.watchEvents([]*clientv3.Event{
		{
			Type: clientv3.EventTypeDelete,
			Kv:   &mvccpb.KeyValue{Key: []byte("/test/127.0.0.1:10000")},
		},
	})
	_, ok = rl.Get("test")
	if ok {
		t.Error("Expect return not ok")
	}

	select {
	case got := <-gotCh:
		if got.Name != "test" {
			t.Error("Expect Name is test")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout")
	}
}
