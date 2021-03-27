package internalapi

import (
	"net/http"
	"net/http/pprof"

	"github.com/julienschmidt/httprouter"

	"go.f110.dev/heimdallr/pkg/server"
)

type Prof struct {
}

var _ server.ChildServer = &Prof{}

func NewProf() *Prof {
	return &Prof{}
}

func (p *Prof) Route(mux *httprouter.Router) {
	mux.HandlerFunc(http.MethodGet, "/pprof/", pprof.Index)
	mux.HandlerFunc(http.MethodGet, "/pprof/cmdline", pprof.Cmdline)
	mux.HandlerFunc(http.MethodGet, "/pprof/profile", pprof.Profile)
	mux.HandlerFunc(http.MethodGet, "/pprof/symbol", pprof.Symbol)
	mux.HandlerFunc(http.MethodGet, "/pprof/trace", pprof.Trace)
}
