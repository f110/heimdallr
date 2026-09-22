package stat

import (
	"sync/atomic"
)

var Value = &Stat{}

type Stat struct {
	activeSocket atomic.Int64
	activeAgent  atomic.Int64
}

func (s *Stat) ActiveSocketProxyConn() int64 {
	return s.activeSocket.Load()
}

func (s *Stat) OpenSocketProxyConn() {
	s.activeSocket.Add(1)
}

func (s *Stat) CloseSocketProxyConn() {
	s.activeSocket.Add(-1)
}

func (s *Stat) ActiveAgent() int64 {
	return s.activeAgent.Load()
}

func (s *Stat) NewAgent() {
	s.activeAgent.Add(1)
}

func (s *Stat) RemoveAgent() {
	s.activeAgent.Add(-1)
}
