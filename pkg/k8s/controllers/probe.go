package controllers

import (
	"net/http"
	"sync"

	"golang.org/x/xerrors"
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
	if err := p.s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return xerrors.Errorf(": %w", err)
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
