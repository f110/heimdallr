package connector

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc/rpcclient"
	"github.com/f110/lagrangian-proxy/pkg/stat"
)

const (
	ProtocolName               = "lc1"
	DefaultCertificatePassword = "ZRechGaCSqBPdtTZ599Ivw"
)

const (
	OpcodeDial uint8 = 1 + iota
	OpcodeDialSuccess
	OpcodePacket
	OpcodeHeartbeat
)

var (
	heartbeatDuration = 30 * time.Second
)

type Stream struct{}

type Frame struct {
	msg    *bytes.Buffer
	header []byte
}

func NewFrame() *Frame {
	return &Frame{
		msg:    new(bytes.Buffer),
		header: make([]byte, 5),
	}
}

func (f *Frame) Write(b []byte) (n int, err error) {
	return f.msg.Write(b)
}

func (f *Frame) Reset() {
	f.msg.Reset()
}

func (f *Frame) EncodeTo(opCode uint8, w io.Writer) (n int, err error) {
	f.header[0] = opCode
	binary.BigEndian.PutUint32(f.header[1:5], uint32(f.msg.Len()))
	n, err = w.Write(append(f.header, f.msg.Bytes()...))
	f.Reset()
	return n, err
}

type Conn struct {
	conn       *tls.Conn
	r          io.ReadCloser
	remoteAddr *net.TCPAddr
	streamId   uint32
	idBuf      []byte
	f          *Frame
}

func NewConn(conn *tls.Conn, streamId uint32, r io.ReadCloser, remoteAddr *net.TCPAddr) *Conn {
	idBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(idBuf, streamId)
	return &Conn{
		conn:       conn,
		remoteAddr: remoteAddr,
		streamId:   streamId,
		f:          NewFrame(),
		r:          r,
		idBuf:      idBuf,
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.f.Write(c.idBuf)
	c.f.Write(b)
	n, err = c.f.EncodeTo(OpcodePacket, c.conn)
	if err == nil {
		return n - 5, nil
	}
	return n, err
}

func (c *Conn) Close() error {
	return c.r.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type ConnThroughRelay struct {
	conn          *tls.Conn
	streamId      uint32
	remoteAddr    *net.TCPAddr
	idBuf         []byte
	f             *Frame
	reader        io.ReadCloser
	writer        io.Writer
	dialSuccessCh chan *dialSuccess
}

func NewConnThroughRelay(ctx context.Context, conn *tls.Conn) (*ConnThroughRelay, error) {
	reader, writer := io.Pipe()
	c := &ConnThroughRelay{
		conn:   conn,
		f:      NewFrame(),
		reader: reader,
		writer: writer,
	}
	go c.readUpstream()

	id := make([]byte, 4)
	i, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	binary.BigEndian.PutUint32(id, uint32(i.Int64()))

	c.dialSuccessCh = make(chan *dialSuccess)

	f := NewFrame()
	f.Write(id)
	f.EncodeTo(OpcodeDial, conn)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case su := <-c.dialSuccessCh:
		c.streamId = su.streamId
		c.remoteAddr = su.remoteAddr
		c.idBuf = make([]byte, 4)
		binary.BigEndian.PutUint32(c.idBuf, su.streamId)
	}

	return c, nil
}

func (c *ConnThroughRelay) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

func (c *ConnThroughRelay) Write(b []byte) (n int, err error) {
	c.f.Write(c.idBuf)
	c.f.Write(b)
	n, err = c.f.EncodeTo(OpcodePacket, c.conn)
	if err == nil {
		return n - 5, nil
	}

	c.Close()
	return n, err
}

func (c *ConnThroughRelay) Close() error {
	c.reader.Close()
	return c.conn.Close()
}

func (c *ConnThroughRelay) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *ConnThroughRelay) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *ConnThroughRelay) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *ConnThroughRelay) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *ConnThroughRelay) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *ConnThroughRelay) readUpstream() {
	defer c.Close()

	header := make([]byte, 5)
	buf := make([]byte, 4*1024)
	for {
		n, err := io.ReadFull(c.conn, header)
		if err != nil {
			logger.Log.Debug("Failure read header", zap.Error(err))
			return
		}
		if n != 5 {
			logger.Log.Debug("Invalid header")
			return
		}

		bodySize := binary.BigEndian.Uint32(header[1:5])
		if cap(buf) < int(bodySize) {
			buf = make([]byte, int(bodySize))
		}

		n, err = io.ReadAtLeast(c.conn, buf, int(bodySize))
		if err != nil {
			logger.Log.Debug("Failure read body", zap.Error(err))
			return
		}
		if n != int(bodySize) {
			logger.Log.Debug("Could not read all body", zap.Int("readed", n), zap.Uint32("body_size", bodySize))
			return
		}
		switch header[0] {
		case OpcodePacket:
			c.writer.Write(buf[4:bodySize])
		case OpcodeDialSuccess:
			streamId := binary.BigEndian.Uint32(buf[4:8])
			addrLen := net.IPv4len
			if buf[8] == AddrTypeV6 {
				addrLen = net.IPv6len
			}
			ipAddr := make([]byte, addrLen)
			copy(ipAddr, buf[9:9+addrLen])
			port := binary.BigEndian.Uint32(buf[9+addrLen : 9+addrLen+4])
			addr := &net.TCPAddr{IP: ipAddr, Port: int(port)}

			c.dialSuccessCh <- &dialSuccess{streamId: streamId, remoteAddr: addr}
		case OpcodeHeartbeat:
			c.conn.SetReadDeadline(time.Now().Add(heartbeatDuration * 2))
			logger.Log.Debug("Got heartbeat of relay")
		default:
			logger.Log.Debug("unknown type", zap.Uint8("opcode", header[0]))
		}
	}
}

type Dialer struct {
	name   string
	server *Server
}

func NewDialer(s *Server, name string) *Dialer {
	return &Dialer{name: name, server: s}
}

func (d *Dialer) DialContext(ctx context.Context, _network, _addr string) (net.Conn, error) {
	return d.server.DialUpstream(ctx, d.name)
}

type dialSuccess struct {
	streamId   uint32
	remoteAddr *net.TCPAddr
}

type Server struct {
	Config  *config.Config
	Locator database.RelayLocator
	Pool    *ConnectionManager
	client  *rpcclient.Client

	mu            sync.RWMutex
	conns         map[string]*tls.Conn
	dials         map[uint32]chan *dialSuccess
	serveStreams  map[uint32]io.Writer
	roundTrippers map[string]http.RoundTripper
}

func NewServer(conf *config.Config, rpcConn *grpc.ClientConn, locator database.RelayLocator) *Server {
	c, _ := rpcclient.NewClientForInternal(rpcConn, conf.General.InternalToken)

	return &Server{
		Config:        conf,
		Locator:       locator,
		Pool:          NewConnectionManager(conf, locator),
		client:        c,
		conns:         make(map[string]*tls.Conn),
		dials:         make(map[uint32]chan *dialSuccess),
		serveStreams:  make(map[uint32]io.Writer),
		roundTrippers: make(map[string]http.RoundTripper),
	}
}

func (s *Server) Accept(_ *http.Server, conn *tls.Conn, _ http.Handler) {
	logger.Log.Debug("Accept connector", zap.String("name", conn.ConnectionState().PeerCertificates[0].Subject.CommonName))
	b, ok := s.Config.General.GetBackend(conn.ConnectionState().PeerCertificates[0].Subject.CommonName)
	if !ok {
		logger.Log.Info("Unknown host", zap.String("name", conn.ConnectionState().PeerCertificates[0].Subject.CommonName))
		return
	}
	if !b.Agent {
		logger.Log.Info("Not agent host", zap.String("name", b.Name))
		return
	}
	s.setUpstreamConn(b.Name, conn)
	defer s.deleteUpstreamConn(b.Name)

	stat.Value.NewAgent()
	defer stat.Value.RemoveAgent()

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	go s.heartbeat(ctx, conn)

	relay, err := NewRelay(s.client, b.Name, s, conn)
	if err != nil {
		logger.Log.Warn("Can not start relay", zap.Error(err))
		return
	}
	go func() {
		if err := relay.Serve(); err != nil {
			return
		}
	}()
	defer relay.Close()

	err = s.Serve(conn)
	if err != nil && err != io.EOF {
		logger.Log.Info("Something occurred", zap.Error(err))
	}
}

func (s *Server) Serve(conn net.Conn) error {
	header := make([]byte, 5)
	buf := make([]byte, 4*1024)
	for {
		n, err := io.ReadFull(conn, header)
		if err != nil {
			return err
		}
		if n != 5 {
			return xerrors.New("connector: invalid header")
		}

		bodySize := binary.BigEndian.Uint32(header[1:5])
		switch header[0] {
		case OpcodeDialSuccess:
			_, err := io.ReadAtLeast(conn, buf[:bodySize], int(bodySize))
			if err != nil {
				continue
			}
			dialId := binary.BigEndian.Uint32(buf[:4])
			streamId := binary.BigEndian.Uint32(buf[4:8])
			addrLen := net.IPv4len
			if buf[8] == AddrTypeV6 {
				addrLen = net.IPv6len
			}
			ipAddr := make([]byte, addrLen)
			copy(ipAddr, buf[9:9+addrLen])
			port := binary.BigEndian.Uint32(buf[9+addrLen : 9+addrLen+4])
			addr := &net.TCPAddr{IP: ipAddr, Port: int(port)}

			s.mu.Lock()
			ch := s.dials[dialId]
			delete(s.dials, dialId)
			s.mu.Unlock()

			select {
			case ch <- &dialSuccess{streamId: streamId, remoteAddr: addr}:
			default:
			}
		case OpcodePacket:
			if cap(buf) < int(bodySize) {
				buf = make([]byte, bodySize)
			}
			_, err := io.ReadAtLeast(conn, buf[:bodySize], int(bodySize))
			if err != nil {
				continue
			}
			streamId := binary.BigEndian.Uint32(buf[:4])
			s.mu.Lock()
			c := s.serveStreams[streamId]
			s.mu.Unlock()
			switch c.(type) {
			case *tls.Conn:
				// if c is *tls.Conn, then It's Relay connection.
				c.Write(append(header, buf[:bodySize]...))
			default:
				c.Write(buf[4:bodySize])
			}
		case OpcodeHeartbeat:
			conn.SetReadDeadline(time.Now().Add(heartbeatDuration * 2))
			logger.Log.Debug("Got heartbeat")
		}
	}
}

func (s *Server) DialUpstream(ctx context.Context, name string) (net.Conn, error) {
	b, ok := s.Config.General.GetBackend(name)
	if !ok {
		return nil, xerrors.New("connector: backend not found")
	}
	conn, ok := s.getUpstreamConn(b.Name)
	if !ok {
		c, err := s.dialUpstreamViaRelay(ctx, b)
		if err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}
		return c, nil
	}

	id := make([]byte, 4)
	i, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	binary.BigEndian.PutUint32(id, uint32(i.Int64()))

	ch := make(chan *dialSuccess)
	s.mu.Lock()
	s.dials[uint32(i.Int64())] = ch
	s.mu.Unlock()

	f := NewFrame()
	f.Write(id)
	f.EncodeTo(OpcodeDial, conn)

	select {
	case <-time.After(5 * time.Second):
		return nil, xerrors.New("connector: time out")
	case <-ctx.Done():
		return nil, xerrors.New("connector: canceled")
	case su := <-ch:
		r, w := io.Pipe()
		c := NewConn(conn, su.streamId, r, su.remoteAddr)

		s.mu.Lock()
		s.serveStreams[su.streamId] = w
		s.mu.Unlock()
		return c, nil
	}
}

func (s *Server) dialUpstreamViaRelay(ctx context.Context, b *config.Backend) (net.Conn, error) {
	conn, err := s.Pool.GetConn(b.Name)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	return NewConnThroughRelay(ctx, conn)
}

func (s *Server) DialUpstreamForRelay(ctx context.Context, name string, w io.Writer, dialId uint32) (uint32, *net.TCPAddr, error) {
	b, ok := s.Config.General.GetBackend(name)
	if !ok {
		return 0, nil, xerrors.New("connector: backend not found")
	}
	conn, ok := s.getUpstreamConn(b.Name)
	if !ok {
		return 0, nil, xerrors.New("connector: backend not connected")
	}

	id := make([]byte, 4)
	binary.BigEndian.PutUint32(id, dialId)

	ch := make(chan *dialSuccess)
	s.mu.Lock()
	s.dials[dialId] = ch
	s.mu.Unlock()

	f := NewFrame()
	f.Write(id)
	f.EncodeTo(OpcodeDial, conn)

	select {
	case <-time.After(5 * time.Second):
		return 0, nil, xerrors.New("connector: time out")
	case <-ctx.Done():
		return 0, nil, xerrors.New("connector: canceled")
	case su := <-ch:
		s.mu.Lock()
		s.serveStreams[su.streamId] = w
		s.mu.Unlock()
		return su.streamId, su.remoteAddr, nil
	}
}

func (s *Server) RoundTrip(backend *config.Backend, req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	rt, ok := s.roundTrippers[backend.Name]
	s.mu.Unlock()
	if ok {
		return rt.RoundTrip(req)
	}

	d := NewDialer(s, backend.Name)
	rt = &http.Transport{
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxConnsPerHost:       16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	s.mu.Lock()
	s.roundTrippers[backend.Name] = rt
	s.mu.Unlock()

	return rt.RoundTrip(req)
}

func (s *Server) heartbeat(ctx context.Context, conn net.Conn) {
	t := time.NewTicker(heartbeatDuration)
	f := NewFrame()
	conn.SetReadDeadline(time.Now().Add(heartbeatDuration * 2))
	for {
		select {
		case <-t.C:
			conn.SetWriteDeadline(time.Now().Add(heartbeatDuration * 2))
			f.EncodeTo(OpcodeHeartbeat, conn)
			logger.Log.Debug("Write heartbeat")
		case <-ctx.Done():
			return
		}
	}
	t.Stop()
}

func (s *Server) getUpstreamConn(name string) (*tls.Conn, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	conn, ok := s.conns[name]
	return conn, ok
}

func (s *Server) setUpstreamConn(name string, conn *tls.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.conns[name] = conn
}

func (s *Server) deleteUpstreamConn(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.conns, name)
}
