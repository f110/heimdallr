package frontproxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"golang.org/x/net/http2"
)

type FrontendProxy struct {
	server *http.Server
}

func NewFrontendProxy() *FrontendProxy {
	return &FrontendProxy{}
}

func (p *FrontendProxy) Serve() error {
	l, err := net.Listen("tcp", "")
	if err != nil {
		return err
	}
	listener := tls.NewListener(l, &tls.Config{})

	server := &http.Server{}
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		return err
	}
	p.server = server

	return server.Serve(listener)
}

func (p *FrontendProxy) Shutdown(ctx context.Context) error {
	if p.server == nil {
		return nil
	}

	return p.server.Shutdown(ctx)
}
