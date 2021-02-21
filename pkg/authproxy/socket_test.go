package authproxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.f110.dev/heimdallr/pkg/auth"
	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/database/memory"
	"go.f110.dev/heimdallr/pkg/netutil"
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
	require.Greater(t, len(buf), 5, "response message is short")
	require.Equal(t, buf[0], TypeMessage, "response message type is not TypeMessage")
	length := binary.BigEndian.Uint32(buf[1:5])
	require.Greaterf(t, len(buf), int(5+length), "length field is invalid: %v %v", len(buf), 5+length)

	query := buf[5 : 5+length]
	value, err := url.ParseQuery(string(query))
	require.NoError(t, err)
	msgErr, err := ParseMessageError(value)
	require.NoError(t, err)

	return msgErr
}

func TestNewSocketProxy(t *testing.T) {
	v := NewSocketProxy(&configv2.Config{}, nil)
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

	ca, caPrivateKey, err := cert.CreateCertificateAuthority("test", "", "", "jp")
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(ca)
	// Private key for the client is not needed.
	clientCert, _, err := cert.GenerateMutualTLSCertificate(ca, caPrivateKey, []string{"test"}, nil)
	require.NoError(t, err)

	user := memory.NewUserDatabase()
	token := memory.NewTokenDatabase()
	socketProxy := NewSocketProxy(&configv2.Config{
		AccessProxy: &configv2.AccessProxy{
			ServerNameHost: "example.com",
			TokenEndpoint:  "http://token.example.com",
			Backends: []*configv2.Backend{
				{Name: "socket", Socket: &configv2.SocketBackend{}},
				{Name: "success", Socket: &configv2.SocketBackend{Upstream: fmt.Sprintf("tcp://:%d", backendAddr.Port)}},
			},
		},
		AuthorizationEngine: &configv2.AuthorizationEngine{
			Roles: []*configv2.Role{
				{Name: "test", Bindings: []*configv2.Binding{
					{Backend: "socket"},
					{Backend: "success"},
				}},
			},
		},
		CertificateAuthority: &configv2.CertificateAuthority{
			Local: &configv2.CertificateAuthorityLocal{
				CertPool: caPool,
			},
		},
	}, nil)
	err = socketProxy.Config.AccessProxy.Setup(socketProxy.Config.AccessProxy.Backends)
	if err != nil {
		t.Fatal(err)
	}
	err = socketProxy.Config.AuthorizationEngine.Setup(socketProxy.Config.AuthorizationEngine.Roles, []*configv2.RPCPermission{})
	if err != nil {
		t.Fatal(err)
	}
	_ = user.Set(nil, &database.User{Id: "test@example.com", Roles: []string{"test"}})
	userToken, _ := token.SetUser("test@example.com")
	auth.Init(socketProxy.Config, nil, user, token, nil)

	t.Run("Handshake failure", func(t *testing.T) {
		conn := newTLSConn(tls.ConnectionState{
			ServerName:       "socket.example.com",
			PeerCertificates: []*x509.Certificate{clientCert},
		}, bytes.NewBuffer([]byte{0x00}))

		socketProxy.Accept(nil, conn, nil)

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
			ServerName:       "socket.example.com",
			PeerCertificates: []*x509.Certificate{clientCert},
		}, data)

		socketProxy.Accept(nil, conn, nil)

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
			ServerName:       "socket.example.com",
			PeerCertificates: []*x509.Certificate{clientCert},
		}, data)

		socketProxy.Accept(nil, conn, nil)

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
			ServerName:       "success.example.com",
			PeerCertificates: []*x509.Certificate{clientCert},
		}, data)

		socketProxy.Accept(nil, conn, nil)

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

func TestNewClient(t *testing.T) {
	r, w := io.Pipe()
	v := NewSocketProxyClient(r, w)
	if v == nil {
		t.Error("NewSocketProxyClient should return a value")
	}
}

func TestClient_Dial(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}

	ca, caPrivateKey, err := cert.CreateCertificateAuthority("test", "", "", "jp")
	if err != nil {
		t.Fatal(err)
	}
	serverCert, serverPrivKey, err := cert.GenerateServerCertificate(ca, caPrivateKey, []string{hostname})
	if err != nil {
		t.Fatal(err)
	}
	cCert, clientPrivKey, err := cert.GenerateMutualTLSCertificate(ca, caPrivateKey, []string{"test"}, nil)
	require.NoError(t, err)
	clientCert := &tls.Certificate{
		Certificate: [][]byte{cCert.Raw},
		PrivateKey:  clientPrivKey,
	}

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		port, err := netutil.FindUnusedPort()
		if err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			t.Fatal(err)
		}
		tlsListener := tls.NewListener(l, &tls.Config{
			ServerName: hostname,
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{serverCert.Raw},
					PrivateKey:  serverPrivKey,
				},
			},
		})
		go func() {
			c, err := tlsListener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			conn := c.(*tls.Conn)
			if err := conn.Handshake(); err != nil {
				t.Fatal(err)
			}

			buf := make([]byte, 5)
			if _, err := conn.Read(buf); err != nil {
				t.Fatal(err)
			}
			if buf[0] != TypeOpen {
				t.Errorf("Expect TypeOpen: %v", buf[0])
			}
			l := binary.BigEndian.Uint32(buf[1:5])
			buf = make([]byte, l)
			if _, err := conn.Read(buf); err != nil {
				t.Fatal(err)
			}
			conn.Write([]byte{TypeOpenSuccess, 0, 0, 0, 0})
		}()

		r, w := io.Pipe()
		v := NewSocketProxyClient(r, w)
		err = v.Dial("", fmt.Sprintf("%d", port), clientCert, "test-token", net.DefaultResolver)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Not has privilege", func(t *testing.T) {
		t.Parallel()

		port, err := netutil.FindUnusedPort()
		if err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			t.Fatal(err)
		}
		tlsListener := tls.NewListener(l, &tls.Config{
			ServerName: hostname,
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{serverCert.Raw},
					PrivateKey:  serverPrivKey,
				},
			},
		})

		go func() {
			c, err := tlsListener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			conn := c.(*tls.Conn)
			if err := conn.Handshake(); err != nil {
				t.Fatal(err)
			}

			buf := make([]byte, 5)
			if _, err := conn.Read(buf); err != nil {
				t.Fatal(err)
			}
			if buf[0] != TypeOpen {
				t.Errorf("Expect TypeOpen: %v", buf[0])
			}
			l := binary.BigEndian.Uint32(buf[1:5])
			buf = make([]byte, l)
			if _, err := conn.Read(buf); err != nil {
				t.Fatal(err)
			}

			v := &url.Values{}
			v.Set("code", "3")
			v.Set("msg", "You don't have privilege")
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(v.Encode())))
			res := new(bytes.Buffer)
			res.WriteByte(TypeMessage)
			res.Write(lenBuf)
			res.WriteString(v.Encode())
			res.WriteTo(conn)
		}()

		r, w := io.Pipe()
		v := NewSocketProxyClient(r, w)
		err = v.Dial("", fmt.Sprintf("%d", port), clientCert, "test-token", net.DefaultResolver)
		require.Error(t, err)
		msgErr, ok := err.(MessageError)
		require.True(t, ok, "Expect return MessageError")
		assert.Equal(t, 3, msgErr.Code())
	})
}
