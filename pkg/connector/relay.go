package connector

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"go.f110.dev/xerrors"
	"go.uber.org/zap"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/netutil"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
)

type Relay struct {
	Addr     *net.TCPAddr
	name     string
	address  string
	server   *Server
	conn     *tls.Conn
	listener net.Listener

	mu       sync.Mutex
	accepted map[string]net.Conn
}

func NewRelay(client *rpcclient.Client, name string, server *Server, conn *tls.Conn) (*Relay, error) {
	hostname, err := netutil.GetHostname()
	if err != nil {
		return nil, err
	}

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	addr := l.Addr().(*net.TCPAddr)

	subject := pkix.Name{
		CommonName: hostname,
	}
	csr, privateKey, err := cert.CreatePrivateKeyAndCertificateRequest(subject, []string{hostname})
	if err != nil {
		return nil, err
	}
	c, err := client.NewServerCert(csr)
	if err != nil {
		return nil, err
	}
	listener := tls.NewListener(l, &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{c},
				PrivateKey:  privateKey,
			},
		},
	})

	address := fmt.Sprintf("%s:%d", hostname, addr.Port)
	err = server.Locator.Set(
		context.Background(),
		&database.Relay{
			Name:        name,
			Addr:        address,
			FromAddr:    conn.RemoteAddr().String(),
			ConnectedAt: time.Now(),
			UpdatedAt:   time.Now(),
		},
	)
	if err != nil {
		l.Close()
		return nil, err
	}

	return &Relay{
		Addr:     addr,
		name:     name,
		address:  address,
		server:   server,
		conn:     conn,
		listener: listener,
		accepted: make(map[string]net.Conn),
	}, nil
}

func (r *Relay) Serve() error {
	logger.Log.Debug("Start relay", zap.String("for", r.name), zap.String("addr", r.Addr.String()))
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			break
		}
		go r.acceptConn(conn)
	}
	logger.Log.Debug("Close relay listener", zap.String("name", r.name))
	return nil
}

func (r *Relay) Close() {
	if err := r.server.Locator.Delete(context.Background(), r.name, r.address); err != nil {
		logger.Log.Info("Failure delete relay record", zap.Error(err))
	}
	r.listener.Close()
	for _, c := range r.accepted {
		c.Close()
	}
}

func (r *Relay) acceptConn(childConn net.Conn) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	defer childConn.Close()

	r.mu.Lock()
	r.accepted[childConn.RemoteAddr().String()] = childConn
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		delete(r.accepted, childConn.RemoteAddr().String())
	}()

	header := make([]byte, 5)
	buf := make([]byte, 4*1024)
	for {
		_, err := io.ReadFull(childConn, header)
		if err != nil {
			return
		}

		bodySize := binary.BigEndian.Uint32(header[1:5])
		if cap(buf) < int(bodySize) {
			buf = make([]byte, bodySize)
		}
		var n int
		if bodySize > 0 {
			n, err = io.ReadAtLeast(childConn, buf, int(bodySize))
			if err != nil {
				return
			}
		}

		switch header[0] {
		case OpcodeDial:
			dialId := binary.BigEndian.Uint32(buf[:4])
			streamId, addr, err := r.server.DialUpstreamForRelay(ctx, r.name, childConn, dialId)
			if err != nil {
				return
			}
			b := make([]byte, 9+len(addr.IP)+4)
			binary.BigEndian.PutUint32(b[:4], dialId)
			binary.BigEndian.PutUint32(b[4:8], streamId)
			buf[8] = AddrTypeV4
			if len(addr.IP) == net.IPv6len {
				buf[8] = AddrTypeV6
			}
			copy(buf[9:9+len(addr.IP)], addr.IP)
			binary.BigEndian.PutUint32(buf[9+len(addr.IP):9+len(addr.IP)+4], uint32(addr.Port))
			logger.Log.Debug("dial success", zap.Int32("Dial id", int32(dialId)), zap.Uint32("stream id", streamId))
			f := NewFrame()
			f.Write(b)
			f.EncodeTo(OpcodeDialSuccess, childConn)
		case OpcodeHeartbeat:
			childConn.SetWriteDeadline(time.Now().Add(heartbeatDuration * 2))
			childConn.Write(header)
			logger.Log.Debug("Write heartbeat of relay")
		default:
			r.conn.Write(append(header, buf[:n]...))
		}
	}
}
