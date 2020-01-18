package frontproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/f110/lagrangian-proxy/pkg/auth"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/connector"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/stat"
)

const (
	SocketProxyNextProto = "lpsc1"
	bufferSize           = 4096
)

const (
	TypeOpen uint8 = 1 + iota
	TypeOpenSuccess
	TypePacket
	TypeMessage
	TypePing
	TypePong
)

const (
	SocketErrorCodeInvalidProtocol = 1 + iota
	SocketErrorCodeRequestAuth
	SocketErrorCodeNotAccessible
	SocketErrorCodeCloseConnection
)

var (
	SocketErrorInvalidProtocol = NewMessageError(SocketErrorCodeInvalidProtocol, "invalid protocol")
	SocketErrorRequestAuth     = NewMessageError(SocketErrorCodeRequestAuth, "need authenticate")
	SocketErrorNotAccessible   = NewMessageError(SocketErrorCodeNotAccessible, "You don't have capability")
	SocketErrorCloseConnection = NewMessageError(SocketErrorCodeCloseConnection, "Sorry, the server has to close connection")
)

var (
	HeartbeatInterval = 30 * time.Second
)

type MessageError interface {
	error
	Code() int
	Message() string
	Params() url.Values
	Clone() MessageError
}

type messageError struct {
	code    int
	message string
	params  url.Values
}

func NewMessageError(code int, message string) MessageError {
	return &messageError{code: code, message: message}
}

func (e *messageError) Error() string {
	return fmt.Sprintf("frontproxy: %s (code=%d)", e.message, e.code)
}

func (e *messageError) Code() int {
	return e.code
}

func (e *messageError) Message() string {
	return e.message
}

func (e *messageError) Params() url.Values {
	return e.params
}

func (e *messageError) Clone() MessageError {
	v, _ := url.ParseQuery(e.params.Encode())
	return &messageError{code: e.code, message: e.message, params: v}
}

func ParseMessageError(v url.Values) (MessageError, error) {
	i, err := strconv.Atoi(v.Get("code"))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	msg := v.Get("msg")
	v.Del("code")
	v.Del("msg")

	return &messageError{code: i, message: msg, params: v}, nil
}

type Stream struct {
	conn   *tls.Conn
	parent *SocketProxy
	token  string
	host   string

	closeOnce   sync.Once
	user        *database.User
	backend     *config.Backend
	backendConn net.Conn
}

type SocketProxy struct {
	Config    *config.Config
	connector *connector.Server

	mu    sync.Mutex
	conns map[string]*Stream
}

func NewSocketProxy(conf *config.Config, ct *connector.Server) *SocketProxy {
	return &SocketProxy{Config: conf, connector: ct, conns: make(map[string]*Stream, 0)}
}

func (s *SocketProxy) Accept(_ *http.Server, conn *tls.Conn, _ http.Handler) {
	logger.Log.Debug("Accept new socket", zap.String("server_name", conn.ConnectionState().ServerName))
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	defer conn.Close()

	stat.Value.OpenSocketProxyConn()
	defer stat.Value.CloseSocketProxyConn()

	st := NewStream(s, conn, conn.ConnectionState().ServerName)
	defer st.close()

	s.mu.Lock()
	s.conns[conn.RemoteAddr().String()] = st
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn.RemoteAddr().String())
		s.mu.Unlock()
	}()

	if err := st.handshake(); err != nil {
		logger.Log.Info("Failure handshake", zap.Error(err))
		return
	}
	if err := st.authenticate(ctx, s.Config.General.TokenEndpoint); err != nil {
		logger.Log.Info("Failure authenticate", zap.Error(err))
		return
	}
	if err := st.dialBackend(ctx); err != nil {
		logger.Log.Info("Failure dial backend", zap.Error(err))
		return
	}
	if err := st.pipe(); err != nil && !isClosedNetwork(err) {
		logger.Log.Info("Close pipe", zap.Error(err))
		return
	}
}

func (s *SocketProxy) Shutdown() {
	for _, st := range s.conns {
		go st.close()
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
	if buf[0] != TypeOpen {
		st.sendMessage(SocketErrorInvalidProtocol)
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

func (st *Stream) authenticate(ctx context.Context, endpoint string) error {
	user, err := auth.AuthenticateForSocket(ctx, st.token, st.host)
	switch err {
	case auth.ErrNotAllowed, auth.ErrUserNotFound, auth.ErrHostnameNotFound:
		st.sendMessage(SocketErrorNotAccessible)
		return err
	case auth.ErrInvalidToken:
		e := SocketErrorRequestAuth.Clone()
		e.Params().Set("endpoint", endpoint)
		st.sendMessage(e)
		return err
	}
	if err != nil {
		logger.Log.Error("Unhandled error", zap.Error(err))
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
	var conn net.Conn
	var err error
	if st.backend.Agent {
		d := connector.NewDialer(st.parent.connector, st.backend.Name)
		conn, err = d.DialContext(ctx, "", "")
	} else {
		conn, err = (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", st.backend.Url.Host)
	}
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	st.backendConn = conn
	buf := make([]byte, 5)
	buf[0] = TypeOpenSuccess
	st.conn.Write(buf)
	return nil
}

func (st *Stream) pipe() error {
	logger.Log.Debug("Start duplex connection")
	go func() {
		if err := st.readBackend(); err != nil {
			logger.Log.Info("Something occurred during to read from backend", zap.Error(err))
		}
		st.close()
	}()
	go st.heartbeat()

	return st.readConn()
}

func (st *Stream) readBackend() error {
	readBuffer := make([]byte, bufferSize)
	header := make([]byte, 5)
	header[0] = TypePacket
	for {
		n, err := st.backendConn.Read(readBuffer)
		if err != nil {
			if isClosedNetwork(err) {
				return nil
			} else {
				return xerrors.Errorf(": %v", err)
			}
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

		bodySize := int(binary.BigEndian.Uint32(header[1:5]))
		if cap(readBuffer) < bodySize {
			readBuffer = make([]byte, bodySize)
		}
		n, err = io.ReadAtLeast(r, readBuffer, bodySize)
		if n != bodySize {
			return xerrors.Errorf("frontproxy: invalid body size")
		}

		switch header[0] {
		case TypePacket:
			st.backendConn.Write(readBuffer[:bodySize])
		case TypePong:
			st.conn.SetReadDeadline(time.Now().Add(1 * time.Minute))
		default:
			return xerrors.New("frontproxy: unknown packet type")
		}
	}
}

func (st *Stream) heartbeat() {
	ticker := time.NewTicker(HeartbeatInterval)
	header := make([]byte, 5)
	header[0] = TypePing
	for {
		select {
		case <-ticker.C:
			st.conn.SetWriteDeadline(time.Now().Add(2 * HeartbeatInterval))
			logger.Log.Debug("send heartbeat")
			if _, err := st.conn.Write(header); err != nil {
				st.close()
				return
			}
		}
	}
}

func (st *Stream) close() {
	st.closeOnce.Do(func() {
		st.sendMessage(SocketErrorCloseConnection)
		if st.backendConn != nil {
			st.backendConn.Close()
		}
		if st.conn != nil {
			st.conn.Close()
		}
	})
}

func (st *Stream) sendMessage(errMsg MessageError) {
	v := url.Values{}
	if len(errMsg.Params()) > 0 {
		v = errMsg.Params()
	}
	v.Set("code", strconv.Itoa(errMsg.Code()))
	v.Set("msg", errMsg.Message())
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(len(v.Encode())))
	msg := new(bytes.Buffer)
	msg.WriteByte(TypeMessage)
	msg.Write(buf)
	msg.WriteString(v.Encode())

	st.conn.Write(msg.Bytes())
}

func isClosedNetwork(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed")
}
