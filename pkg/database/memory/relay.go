package memory

import (
	"context"
	"sync"
	"time"

	"go.f110.dev/heimdallr/pkg/database"
)

type RelayLocator struct {
	gone chan *database.Relay
	mu   sync.Mutex
	data map[string]*database.Relay
}

var _ database.RelayLocator = &RelayLocator{}

func NewRelayLocator() *RelayLocator {
	return &RelayLocator{
		gone: make(chan *database.Relay),
		data: make(map[string]*database.Relay),
	}
}

func (r *RelayLocator) Get(name string) (*database.Relay, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	v, ok := r.data[name]
	return v, ok
}

func (r *RelayLocator) Set(ctx context.Context, relay *database.Relay) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.data[relay.Name] = relay
	return nil
}

func (r *RelayLocator) Update(ctx context.Context, relay *database.Relay) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if v, ok := r.data[relay.Name]; ok {
		v.UpdatedAt = time.Now()
	}

	return nil
}

func (r *RelayLocator) Delete(ctx context.Context, name, addr string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	d := r.data[name]
	delete(r.data, name)

	select {
	case r.gone <- d:
	default:
	}

	return nil
}

func (r *RelayLocator) Gone() chan *database.Relay {
	return r.gone
}

func (r *RelayLocator) GetListenedAddrs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	res := make([]string, 0, len(r.data))
	for _, v := range r.data {
		res = append(res, v.Addr)
	}

	return res
}

func (r *RelayLocator) ListAllConnectedAgents() []*database.Relay {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := make([]*database.Relay, 0, len(r.data))
	for _, v := range r.data {
		result = append(result, v)
	}

	return result
}
