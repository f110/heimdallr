package internalapi

import (
	"net/http"

	"github.com/julienschmidt/httprouter"

	"go.f110.dev/heimdallr/pkg/server"
)

type Probe struct {
	readinessFn func() bool
}

var _ server.ChildServer = &Probe{}

func NewProbe(fn func() bool) *Probe {
	p := &Probe{
		readinessFn: fn,
	}

	return p
}

func (p *Probe) Route(mux *httprouter.Router) {
	mux.GET("/liveness", p.Liveness)
	mux.GET("/readiness", p.Readiness)
}

func (p *Probe) Liveness(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {}

func (p *Probe) Readiness(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	if !p.readinessFn() {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
}
