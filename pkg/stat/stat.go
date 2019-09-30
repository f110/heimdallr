package stat

import (
	"sync/atomic"
)

var Value = &Stat{}

type Stat struct {
	activeSocket int64
	activeAgent  int64
}

func (s *Stat) ActiveSocketProxyConn() int64 {
	return atomic.LoadInt64(&s.activeSocket)
}

func (s *Stat) OpenSocketProxyConn() {
	atomic.AddInt64(&s.activeSocket, 1)
}

func (s *Stat) CloseSocketProxyConn() {
	atomic.AddInt64(&s.activeSocket, -1)
}

func (s *Stat) ActiveAgent() int64 {
	return atomic.LoadInt64(&s.activeAgent)
}

func (s *Stat) NewAgent() {
	atomic.AddInt64(&s.activeAgent, 1)
}

func (s *Stat) RemoveAgent() {
	atomic.AddInt64(&s.activeAgent, -1)
}
