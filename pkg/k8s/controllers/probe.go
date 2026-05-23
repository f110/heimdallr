package controllers

import (
	"errors"
	"log/slog"
	"net/http"
	"sync"

	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/logger"
)

type Probe struct {
	s *http.Server

	mu    sync.Mutex
	ready bool
}

func NewProbe(addr string) *Probe {
	p := &Probe{
		s: &http.Server{
			Addr: addr,
		},
	}
	p.s.Handler = p

	return p
}

func (p *Probe) Start() error {
	logger.Log.Info("Start probe server", slog.String("addr", p.s.Addr))
	if err := p.s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return xerrors.WithStack(err)
	}

	return nil
}

func (p *Probe) Ready() {
	p.mu.Lock()
	p.ready = true
	p.mu.Unlock()
}

func (p *Probe) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
}
