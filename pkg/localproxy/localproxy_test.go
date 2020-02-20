package localproxy

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"testing"

	"github.com/f110/lagrangian-proxy/pkg/cert"
	"github.com/f110/lagrangian-proxy/pkg/frontproxy"
	"github.com/f110/lagrangian-proxy/pkg/netutil"
)

func TestNewClient(t *testing.T) {
	r, w := io.Pipe()
	v := NewClient(r, w)
	if v == nil {
		t.Error("NewClient should return a value")
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
		if buf[0] != frontproxy.TypeOpen {
			t.Errorf("Expect TypeOpen: %v", buf[0])
		}
		l := binary.BigEndian.Uint32(buf[1:5])
		buf = make([]byte, l)
		if _, err := conn.Read(buf); err != nil {
			t.Fatal(err)
		}
		conn.Write([]byte{frontproxy.TypeOpenSuccess, 0, 0, 0, 0})
	}()

	r, w := io.Pipe()
	v := NewClient(r, w)
	err = v.Dial("", fmt.Sprintf("%d", port), "test-token")
	if err != nil {
		t.Fatal(err)
	}
}
