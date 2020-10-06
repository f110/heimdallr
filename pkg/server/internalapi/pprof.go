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
	mux.HandlerFunc(http.MethodGet, "/prof/", pprof.Index)
	mux.HandlerFunc(http.MethodGet, "/prof/cmdline", pprof.Cmdline)
	mux.HandlerFunc(http.MethodGet, "/prof/profile", pprof.Profile)
	mux.HandlerFunc(http.MethodGet, "/prof/symbol", pprof.Symbol)
	mux.HandlerFunc(http.MethodGet, "/prof/trace", pprof.Trace)
}
