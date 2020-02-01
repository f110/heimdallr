package frontproxy

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/f110/lagrangian-proxy/pkg/auth"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/database/memory"
)

type dummyTLSConn struct {
	state    tls.ConnectionState
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
}

func newTLSConn(state tls.ConnectionState, data *bytes.Buffer) *dummyTLSConn {
	return &dummyTLSConn{state: state, writeBuf: new(bytes.Buffer), readBuf: data}
}

func (d *dummyTLSConn) Read(b []byte) (n int, err error) {
	return d.readBuf.Read(b)
}

func (d *dummyTLSConn) Write(b []byte) (n int, err error) {
	return d.writeBuf.Write(b)
}

func (d *dummyTLSConn) Close() error {
	return nil
}

func (d *dummyTLSConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (d *dummyTLSConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (d *dummyTLSConn) SetDeadline(t time.Time) error {
	panic("implement me")
}

func (d *dummyTLSConn) SetReadDeadline(t time.Time) error {
	panic("implement me")
}

func (d *dummyTLSConn) SetWriteDeadline(t time.Time) error {
	panic("implement me")
}

func (d *dummyTLSConn) ConnectionState() tls.ConnectionState {
	return d.state
}

func parseResponseMessage(t *testing.T, buf []byte) MessageError {
	if len(buf) < 5 {
		t.Fatal("response message is short")
	}
	if buf[0] != TypeMessage {
		t.Fatalf("expect TypeMessage: %v", buf[0])
	}
	length := binary.BigEndian.Uint32(buf[1:5])
	if len(buf) < int(5+length) {
		t.Fatalf("length field is invalid: %v %v", len(buf), 5+length)
	}

	query := buf[5 : 5+length]
	value, err := url.ParseQuery(string(query))
	if err != nil {
		t.Fatal(err)
	}
	msgErr, err := ParseMessageError(value)
	if err != nil {
		t.Fatal(err)
	}

	return msgErr
}

func TestNewSocketProxy(t *testing.T) {
	v := NewSocketProxy(&config.Config{}, nil)
	if v == nil {
		t.Fatal("NewSocketProxy should return a value")
	}
}

func TestSocketProxy_Accept(t *testing.T) {
	backendListener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	backendAddr := backendListener.Addr().(*net.TCPAddr)
	var backendConn net.Conn
	gotConn := make(chan struct{})
	go func() {
		conn, err := backendListener.Accept()
		if err != nil {
			return
		}
		backendConn = conn
		close(gotConn)
	}()

	user := memory.NewUserDatabase()
	token := memory.NewTokenDatabase()
	v := NewSocketProxy(&config.Config{
		General: &config.General{
			ServerNameHost: "example.com",
			TokenEndpoint:  "http://token.example.com",
			Backends: []*config.Backend{
				{Name: "socket", Socket: true},
				{Name: "success", Socket: true, Upstream: fmt.Sprintf("tcp://:%d", backendAddr.Port)},
			},
			Roles: []*config.Role{
				{Name: "test", Bindings: []*config.Binding{
					{Backend: "socket"},
					{Backend: "success"},
				}},
			},
		},
	}, nil)
	err = v.Config.General.Load(v.Config.General.Backends, v.Config.General.Roles, []*config.RpcPermission{})
	if err != nil {
		t.Fatal(err)
	}
	_ = user.Set(nil, &database.User{Id: "test@example.com", Roles: []string{"test"}})
	userToken, _ := token.SetUser("test@example.com")
	auth.Init(v.Config, nil, user, token, nil)

	t.Run("Handshake failure", func(t *testing.T) {
		conn := newTLSConn(tls.ConnectionState{
			ServerName: "socket.example.com",
		}, bytes.NewBuffer([]byte{0x00}))

		v.Accept(nil, conn, nil)

		msgErr := parseResponseMessage(t, conn.writeBuf.Bytes())
		if msgErr.Code() != SocketErrorCodeInvalidProtocol {
			t.Errorf("expect invalid protocol code: %v", msgErr.Code())
		}
	})

	t.Run("Authentication failure", func(t *testing.T) {
		data := new(bytes.Buffer)
		data.WriteByte(TypeOpen)
		param := &url.Values{}
		param.Add("token", "test")
		q := param.Encode()
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(len(q)))
		data.Write(buf)
		data.WriteString(q)
		conn := newTLSConn(tls.ConnectionState{
			ServerName: "socket.example.com",
		}, data)

		v.Accept(nil, conn, nil)

		msgErr := parseResponseMessage(t, conn.writeBuf.Bytes())
		if msgErr.Code() != SocketErrorCodeRequestAuth {
			t.Errorf("expect request auth: %v", msgErr.Code())
		}
	})

	t.Run("Failed connect to backend", func(t *testing.T) {
		data := new(bytes.Buffer)
		data.WriteByte(TypeOpen)
		param := &url.Values{}
		param.Add("token", userToken.Token)
		q := param.Encode()
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(len(q)))
		data.Write(buf)
		data.WriteString(q)
		conn := newTLSConn(tls.ConnectionState{
			ServerName: "socket.example.com",
		}, data)

		v.Accept(nil, conn, nil)

		msgErr := parseResponseMessage(t, conn.writeBuf.Bytes())
		if msgErr.Code() != SocketErrorCodeServerUnavailable {
			t.Errorf("expect Server unavailable: %v", msgErr.Code())
		}
	})

	t.Run("Success", func(t *testing.T) {
		data := new(bytes.Buffer)
		data.WriteByte(TypeOpen)
		param := &url.Values{}
		param.Add("token", userToken.Token)
		q := param.Encode()
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(len(q)))
		data.Write(buf)
		data.WriteString(q)
		conn := newTLSConn(tls.ConnectionState{
			ServerName: "success.example.com",
		}, data)

		v.Accept(nil, conn, nil)

		select {
		case <-gotConn:
		case <-time.After(1 * time.Second):
			t.Fatal("Timeout")
		}

		if backendConn == nil {
			t.Fatal("did not connect to backend")
		}
	})
}
