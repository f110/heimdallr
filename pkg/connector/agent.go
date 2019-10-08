package connector

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/f110/lagrangian-proxy/pkg/logger"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

const (
	AddrTypeV4 byte = 0x01
	AddrTypeV6 byte = 02
)

type Agent struct {
	id         uint32
	backend    string
	conn       *tls.Conn
	cert       *x509.Certificate
	privateKey crypto.PrivateKey
	caCerts    []*x509.Certificate

	mu    sync.RWMutex
	conns map[uint32]net.Conn
}

func NewAgent(cert *x509.Certificate, privateKey crypto.PrivateKey, caCert []*x509.Certificate, backend string) *Agent {
	return &Agent{
		cert:       cert,
		caCerts:    caCert,
		privateKey: privateKey,
		backend:    backend,
		conns:      make(map[uint32]net.Conn),
	}
}

func (a *Agent) Connect(host string) error {
	ca := x509.NewCertPool()
	ca.AddCert(a.caCerts[0])
	conn, err := tls.Dial("tcp", host, &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{a.cert.Raw},
				PrivateKey:  a.privateKey,
			},
		},
		RootCAs:    ca,
		NextProtos: []string{ProtocolName},
	})
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	a.conn = conn

	return nil
}

func (a *Agent) Serve() error {
	header := make([]byte, 5)
	buf := make([]byte, 1024)
	for {
		_, err := io.ReadFull(a.conn, header)
		if err != nil {
			return err
		}

		bodySize := binary.BigEndian.Uint32(header[1:5])
		if cap(buf) < int(bodySize) {
			buf = make([]byte, bodySize)
		}

		switch header[0] {
		case OpcodeDial:
			_, err := io.ReadAtLeast(a.conn, buf, int(bodySize))
			if err != nil {
				return err
			}
			dialId := binary.BigEndian.Uint32(buf[:4])
			conn, err := net.Dial("tcp", a.backend)
			if err != nil {
				logger.Log.Debug("Failed dial backend", zap.Error(err))
				return err
			}
			streamId := atomic.AddUint32(&a.id, 1)
			a.mu.Lock()
			a.conns[streamId] = conn
			a.mu.Unlock()

			addr := conn.RemoteAddr().(*net.TCPAddr)
			b := make([]byte, 9+len(addr.IP)+4)
			binary.BigEndian.PutUint32(b[:4], dialId)
			binary.BigEndian.PutUint32(b[4:8], streamId)
			// addr type
			if len(addr.IP) == net.IPv6len {
				b[8] = AddrTypeV6
			} else {
				b[8] = AddrTypeV4
			}
			copy(b[9:9+len(addr.IP)], addr.IP)
			binary.BigEndian.PutUint32(b[9+len(addr.IP):9+len(addr.IP)+4], uint32(addr.Port))

			f := NewFrame()
			f.Write(b)
			f.EncodeTo(OpcodeDialSuccess, a.conn)
			go a.readBackend(conn, streamId)
		case OpcodePacket:
			n, err := io.ReadAtLeast(a.conn, buf, int(bodySize))
			if err != nil {
				return err
			}
			streamId := binary.BigEndian.Uint32(buf[:4])
			a.mu.RLock()
			c := a.conns[streamId]
			a.mu.RUnlock()
			c.Write(buf[4:n])
		case OpcodeHeartbeat:
			logger.Log.Debug("Got heartbeat")
			a.conn.SetWriteDeadline(time.Now().Add(heartbeatDuration * 2))
			a.conn.Write(header)
		}
	}
}

func (a *Agent) readBackend(backendConn net.Conn, streamId uint32) {
	f := NewFrame()
	buf := make([]byte, 4*1024)
	id := make([]byte, 4)
	binary.BigEndian.PutUint32(id, streamId)
	for {
		n, err := backendConn.Read(buf)
		if err != nil {
			break
		}
		f.Write(id)
		f.Write(buf[:n])
		f.EncodeTo(OpcodePacket, a.conn)
	}
	logger.Log.Debug("Finish reading backend conn")
}
