package frontproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/f110/lagrangian-proxy/pkg/auth"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

const (
	SocketProxyNextProto = "lpsc1"
	bufferSize           = 4096
)

const (
	CommandOpen uint8 = iota
	CommandPacket
	CommandMessage
)

type Stream struct {
	conn   *tls.Conn
	parent *SocketProxy
	token  string
	host   string

	user        *database.User
	backend     *config.Backend
	backendConn net.Conn
}

type SocketProxy struct {
	Config *config.Config
}

func NewSocketProxy(conf *config.Config) *SocketProxy {
	return &SocketProxy{Config: conf}
}

func (s *SocketProxy) Accept(_ *http.Server, conn *tls.Conn, _ http.Handler) {
	logger.Log.Debug("Accept new socket", zap.String("server_name", conn.ConnectionState().ServerName))
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	defer conn.Close()

	st := NewStream(s, conn, conn.ConnectionState().ServerName)
	defer st.close()
	if err := st.handshake(); err != nil {
		logger.Log.Info("Failure handshake", zap.Error(err))
		return
	}
	if err := st.authenticate(ctx); err != nil {
		logger.Log.Info("Failure authenticate", zap.Error(err))
		return
	}
	if err := st.dialBackend(ctx); err != nil {
		logger.Log.Info("Failure dial backend", zap.Error(err))
		return
	}
	if err := st.pipe(); err != nil {
		logger.Log.Info("Close pipe", zap.Error(err))
		return
	}
}

func NewStream(parent *SocketProxy, conn *tls.Conn, host string) *Stream {
	return &Stream{conn: conn, parent: parent, host: host}
}

func (st *Stream) handshake() error {
	readBuffer := make([]byte, bufferSize)
	msg := new(bytes.Buffer)
	for {
		n, err := st.conn.Read(readBuffer)
		if err != nil {
			logger.Log.Info("Close tls.Conn", zap.Error(err))
			return err
		}
		msg.Write(readBuffer[:n])
		if n == bufferSize {
			continue
		}
		break
	}

	buf := msg.Bytes()
	if buf[0] != CommandOpen {
		return xerrors.New("frontproxy: invalid packet header in handshake")
	}
	l := binary.BigEndian.Uint32(buf[1:5])
	v, err := url.ParseQuery(string(buf[5 : 5+l]))
	if err != nil {
		logger.Log.Debug("Failed parse value", zap.Error(err))
		return err
	}
	st.token = v.Get("token")

	return nil
}

func (st *Stream) authenticate(ctx context.Context) error {
	user, err := auth.AuthenticateForSocket(ctx, st.token, st.host)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	st.user = user

	// host parameter is already checked by AuthenticateForSocket.
	// so skip error check here.
	b, _ := st.parent.Config.General.GetBackendByHostname(st.host)
	st.backend = b

	return nil
}

func (st *Stream) dialBackend(ctx context.Context) error {
	logger.Log.Debug("dial backend", zap.String("addr", st.backend.Url.Host))
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", st.backend.Url.Host)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	st.backendConn = conn
	return nil
}

func (st *Stream) pipe() error {
	go func() {
		if err := st.readBackend(); err != nil {
			logger.Log.Info("Something occurred during to read from backend", zap.Error(err))
			st.close()
		}
	}()

	return st.readConn()
}

func (st *Stream) readBackend() error {
	readBuffer := make([]byte, bufferSize)
	header := make([]byte, 5)
	header[0] = CommandPacket
	for {
		n, err := st.backendConn.Read(readBuffer)
		if err != nil && !isClosedNetwork(err) {
			return xerrors.Errorf(": %v", err)
		}

		binary.BigEndian.PutUint32(header[1:5], uint32(n))
		b := append(header, readBuffer[:n]...)
		st.conn.Write(b)
	}
}

func (st *Stream) readConn() error {
	header := make([]byte, 5)
	readBuffer := make([]byte, bufferSize)
	r := bufio.NewReader(st.conn)
	for {
		n, err := r.Read(header)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if n != 5 {
			return xerrors.New("frontproxy: invalid header")
		}
		if header[0] != CommandPacket {
			return xerrors.New("frontproxy: unknown packet type")
		}
		bodySize := int(binary.BigEndian.Uint32(header[1:5]))
		if cap(readBuffer) < bodySize {
			readBuffer = make([]byte, bodySize)
		}
		n, err = io.ReadAtLeast(r, readBuffer, bodySize)
		if n != bodySize {
			return xerrors.Errorf("frontproxy: invalid body size")
		}

		switch header[0] {
		case CommandPacket:
			st.backendConn.Write(readBuffer[:bodySize])
		}
	}
}

func (st *Stream) close() {
	if st.backendConn != nil {
		st.backendConn.Close()
	}
	if st.conn != nil {
		st.conn.Close()
	}
}

func isClosedNetwork(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed")
}
