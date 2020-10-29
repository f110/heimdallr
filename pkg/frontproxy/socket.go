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

	"go.f110.dev/heimdallr/pkg/auth"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/connector"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/stat"
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
	SocketErrorCodeServerUnavailable
)

var (
	SocketErrorInvalidProtocol   = NewMessageError(SocketErrorCodeInvalidProtocol, "invalid protocol")
	SocketErrorRequestAuth       = NewMessageError(SocketErrorCodeRequestAuth, "need authenticate")
	SocketErrorNotAccessible     = NewMessageError(SocketErrorCodeNotAccessible, "You don't have privilege")
	SocketErrorCloseConnection   = NewMessageError(SocketErrorCodeCloseConnection, "Sorry, the server has close connection")
	SocketErrorServerUnavailable = NewMessageError(SocketErrorCodeServerUnavailable, "Temporary the server unavailable")
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
	conn   tlsConn
	parent *SocketProxy
	token  string
	host   string

	closeOnce   sync.Once
	user        *database.User
	backend     *configv2.Backend
	backendConn net.Conn
	closeCh     chan struct{}
}

type SocketProxy struct {
	Config    *configv2.Config
	connector *connector.Server

	mu    sync.Mutex
	conns map[string]*Stream
}

type tlsConn interface {
	net.Conn
	ConnectionState() tls.ConnectionState
}

func NewSocketProxy(conf *configv2.Config, ct *connector.Server) *SocketProxy {
	return &SocketProxy{Config: conf, connector: ct, conns: make(map[string]*Stream, 0)}
}

// Accept handles incoming connection.
// conn is an established connection that is finished handshake.
func (s *SocketProxy) Accept(_ *http.Server, conn tlsConn, _ http.Handler) {
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
	if err := st.authenticate(ctx, s.Config.AccessProxy.TokenEndpoint); err != nil {
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

func NewStream(parent *SocketProxy, conn tlsConn, host string) *Stream {
	return &Stream{conn: conn, parent: parent, host: host, closeCh: make(chan struct{})}
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

	// AuthenticateForSocket is already check the host parameter inside AuthenticateForSocket.
	// Thus skip error check here.
	b, _ := st.parent.Config.AccessProxy.GetBackendByHostname(st.host)
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
		st.sendMessage(SocketErrorServerUnavailable)
		return xerrors.Errorf(": %v", err)
	}

	st.backendConn = conn
	buf := make([]byte, 5)
	buf[0] = TypeOpenSuccess
	st.conn.Write(buf)
	return nil
}

func (st *Stream) pipe() error {
	logger.Log.Debug("Start duplex connection", zap.String("host", st.host), zap.String("user", st.user.Id))
	go func() {
		if err := st.readBackend(); err != nil {
			logger.Log.Info("Something occurred during to read from backend", zap.Error(err))
		}
		st.close()
	}()
	go st.heartbeat()

	if st.backend.SocketTimeout != nil {
		go func() {
			select {
			case <-st.closeCh:
				break
			case <-time.After(st.backend.SocketTimeout.Duration):
				logger.Log.Info("Close a connection due to timeout", zap.String("host", st.host), zap.String("user", st.user.Id))
				st.close()
			}
		}()
	}

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
		close(st.closeCh)
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

type ErrorTokenAuthorization struct {
	Endpoint string
}

func (e *ErrorTokenAuthorization) Error() string {
	return "frontproxy: token is not available"
}

type Client struct {
	conn  *tls.Conn
	inCh  <-chan []byte
	outCh chan<- []byte
}

func NewSocketProxyClient(in io.Reader, out io.Writer) *Client {
	inCh := make(chan []byte)
	outCh := make(chan []byte)

	go func() {
		packet := new(bytes.Buffer)
		buf := make([]byte, 4*1024)
		for {
			n, err := in.Read(buf)
			if err != nil {
				return
			}
			packet.Write(buf[:n])
			if n == 4*1024 {
				continue
			}
			b := make([]byte, packet.Len())
			copy(b, packet.Bytes())
			packet.Reset()
			inCh <- b
		}
	}()

	go func() {
		for {
			if _, err := out.Write(<-outCh); err != nil {
				return
			}
		}
	}()

	return &Client{inCh: inCh, outCh: outCh}
}

func (c *Client) Dial(host, port, token string) error {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%s", host, port),
		&tls.Config{
			NextProtos:         []string{SocketProxyNextProto},
			InsecureSkipVerify: true,
		},
	)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if err := conn.Handshake(); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	c.conn = conn
	v := &url.Values{}
	v.Set("token", token)
	buf := new(bytes.Buffer)
	buf.WriteByte(TypeOpen)
	l := make([]byte, 4)
	binary.BigEndian.PutUint32(l, uint32(len(v.Encode())))
	buf.Write(l)
	buf.WriteString(v.Encode())
	buf.WriteTo(conn)

	header := make([]byte, 5)
	n, err := c.conn.Read(header)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if n != 5 {
		return xerrors.New("localproxy: invalid header")
	}
	switch header[0] {
	case TypeOpenSuccess:
		return nil
	case TypeMessage:
		bodySize := binary.BigEndian.Uint32(header[1:5])
		buf := make([]byte, bodySize)
		n, err := c.conn.Read(buf)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		if n != int(bodySize) {
			return xerrors.New("localproxy: invalid bodysize")
		}
		e, err := parseMessage(buf)
		if err != nil {
			return xerrors.Errorf(": %v", err)
		}
		switch e.Code() {
		case SocketErrorCodeRequestAuth:
			endpoint := e.Params().Get("endpoint")
			return &ErrorTokenAuthorization{Endpoint: endpoint}
		default:
			return e
		}
	}

	return xerrors.New("localproxy: unhandled error")
}

func (c *Client) Pipe(ctx context.Context) error {
	defer c.conn.Close()

	go func() {
		header := make([]byte, 5)
		header[0] = TypePacket
		for {
			select {
			case buf := <-c.inCh:
				binary.BigEndian.PutUint32(header[1:5], uint32(len(buf)))
				c.conn.Write(append(header, buf...))
			case <-ctx.Done():
				return
			}
		}
	}()

	header := make([]byte, 5)
	buf := make([]byte, 1024)
	r := bufio.NewReader(c.conn)
	for {
		n, err := r.Read(header)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if n != 5 {
			return xerrors.New("localproxy: invalid header")
		}
		switch header[0] {
		case TypeMessage, TypePacket, TypePing:
		default:
			return xerrors.New("localproxy: unknown packet type")
		}
		bodySize := int(binary.BigEndian.Uint32(header[1:5]))
		if cap(buf) < bodySize {
			buf = make([]byte, bodySize)
		}
		n, err = io.ReadAtLeast(r, buf, bodySize)
		if n != bodySize {
			return xerrors.Errorf("localproxy: invalid body size")
		}

		switch header[0] {
		case TypePacket:
			b := make([]byte, bodySize)
			copy(b, buf[:bodySize])
			c.outCh <- b
		case TypeMessage:
			e, err := parseMessage(buf[:bodySize])
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			return e
		case TypePing:
			h := make([]byte, 5)
			h[0] = TypePong
			c.conn.SetWriteDeadline(time.Now().Add(2 * HeartbeatInterval))
			if _, err := c.conn.Write(h); err != nil {
				return xerrors.Errorf(": %v", err)
			}
			c.conn.SetReadDeadline(time.Now().Add(2 * HeartbeatInterval))
		}
	}
}

func parseMessage(buf []byte) (MessageError, error) {
	v, err := url.ParseQuery(string(buf))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	return ParseMessageError(v)
}

func isClosedNetwork(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed")
}
