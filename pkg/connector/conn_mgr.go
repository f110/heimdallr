package connector

import (
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"golang.org/x/xerrors"
)

type ConnectionManager struct {
	MaxConnsPerHost int
	locator         database.RelayLocator
	config          *config.Config

	mu    sync.RWMutex
	conns map[string][]*tls.Conn
}

func NewConnectionManager(conf *config.Config, locator database.RelayLocator) *ConnectionManager {
	p := &ConnectionManager{
		locator: locator,
		config:  conf,
		conns:   make(map[string][]*tls.Conn),
	}
	go p.autoRelease(locator.Gone())

	return p
}

func (p *ConnectionManager) GetConn(name string) (*tls.Conn, error) {
	r, ok := p.locator.Get(name)
	if !ok {
		return nil, xerrors.New("connector: relay not found")
	}

	conn, err := tls.Dial("tcp", r.Addr, &tls.Config{
		RootCAs: p.config.General.CertificateAuthority.CertPool,
	})
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	go p.heartbeat(conn)

	k := r.Name + "/" + r.Addr
	p.mu.Lock()
	if _, ok := p.conns[k]; !ok {
		p.conns[k] = make([]*tls.Conn, 0, 1)
	}
	p.conns[k] = append(p.conns[k], conn)
	p.mu.Unlock()

	return conn, err
}

func (p *ConnectionManager) autoRelease(ch chan *database.Relay) {
	for {
		r := <-ch
		key := r.Name + "/" + r.Addr
		p.mu.Lock()
		conns := p.conns[key]
		p.conns[key] = make([]*tls.Conn, 0)
		p.mu.Unlock()
		for _, v := range conns {
			v.Close()
		}
	}
}

func (p *ConnectionManager) heartbeat(conn net.Conn) {
	t := time.NewTicker(heartbeatDuration)
	f := NewFrame()
	for {
		select {
		case <-t.C:
			conn.SetWriteDeadline(time.Now().Add(heartbeatDuration * 2))
			logger.Log.Debug("Write heartbeat of relay")
			if n, err := f.EncodeTo(OpcodeHeartbeat, conn); err != nil || n != 5 {
				return
			}
		}
	}
	t.Stop()
}
