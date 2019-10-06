package internalapi

import (
	"net/http"
	"sync"
	"time"

	"github.com/f110/lagrangian-proxy/pkg/server"
	"github.com/julienschmidt/httprouter"
)

var (
	ProbeInterval = 1 * time.Minute
)

type Probe struct {
	readinessCh chan struct{}

	mu          sync.Mutex
	lastUpdated time.Time
}

var _ server.ChildServer = &Probe{}

func NewProbe(ch chan struct{}) *Probe {
	p := &Probe{
		readinessCh: ch,
		lastUpdated: time.Now(),
	}
	return p
}

func (p *Probe) Route(mux *httprouter.Router) {
	mux.GET("/liveness", p.Liveness)
	mux.GET("/readiness", p.Readiness)
}

func (p *Probe) Liveness(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {}

func (p *Probe) Readiness(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.lastUpdated.Add(ProbeInterval * 2).Before(time.Now()) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
}

func (p *Probe) read() {
	for {
		select {
		case <-p.readinessCh:
			p.mu.Lock()
			p.lastUpdated = time.Now()
			p.mu.Unlock()
		}
	}
}
