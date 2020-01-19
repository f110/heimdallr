package database

import (
	"context"
	"time"

	"golang.org/x/xerrors"
)

var (
	ErrRelayNotFound = xerrors.New("database: relay not found")
)

type RelayLocator interface {
	Get(name string) (*Relay, bool)
	Set(ctx context.Context, relay *Relay) error
	Update(ctx context.Context, relay *Relay) error
	Delete(ctx context.Context, name, addr string) error
	Gone() chan *Relay
	GetListenedAddrs() []string
	ListAllConnectedAgents() []*Relay
}

type Relay struct {
	Name        string    `json:"name"`
	Addr        string    `json:"addr"`
	FromAddr    string    `json:"from_addr"`
	ConnectedAt time.Time `json:"connected_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Version     int64     `json:"-"`
}
