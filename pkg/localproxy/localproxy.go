package localproxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/f110/lagrangian-proxy/pkg/frontproxy"
	"golang.org/x/xerrors"
)

const (
	ClientRedirectUrl = "http://localhost:6391/callback"
)

type Client struct {
	conn *tls.Conn
}

func Dial(addr string, token string) (*Client, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{
		NextProtos:         []string{frontproxy.SocketProxyNextProto},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	if err := conn.Handshake(); err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	v := &url.Values{}
	v.Set("token", token)
	buf := new(bytes.Buffer)
	buf.WriteByte(frontproxy.CommandOpen)
	l := make([]byte, 4)
	binary.BigEndian.PutUint32(l, uint32(len(v.Encode())))
	buf.Write(l)
	buf.WriteString(v.Encode())
	buf.WriteTo(conn)

	return &Client{conn: conn}, nil
}

func (c *Client) Pipe(in io.Reader, out io.Writer) error {
	go func() {
		buf := make([]byte, 1024)
		header := make([]byte, 5)
		header[0] = frontproxy.CommandPacket
		packet := new(bytes.Buffer)
		for {
			n, err := in.Read(buf)
			if err != nil {
				return
			}
			packet.Write(buf[:n])
			if n == 1024 {
				continue
			}

			binary.BigEndian.PutUint32(header[1:5], uint32(packet.Len()))
			c.conn.Write(append(header, packet.Bytes()...))
			packet.Reset()
		}
	}()

	header := make([]byte, 5)
	buf := make([]byte, 1024)
	r := bufio.NewReader(c.conn)
	for {
		n, err := r.Read(header)
		if err != nil {
			return err
		}
		if n != 5 {
			return xerrors.New("localproxy: invalid header")
		}
		if header[0] != frontproxy.CommandPacket && header[0] != frontproxy.CommandMessage {
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
		case frontproxy.CommandPacket:
			out.Write(buf[:bodySize])
		}
	}
}
