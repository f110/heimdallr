package localproxy

import (
	"bufio"
	"bytes"
	"context"
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

type ErrorTokenAuthorization struct {
	Endpoint string
}

func (e *ErrorTokenAuthorization) Error() string {
	return "localproxy: token is not available"
}

type Client struct {
	conn  *tls.Conn
	inCh  <-chan []byte
	outCh chan<- []byte
}

func NewClient(in io.Reader, out io.Writer) *Client {
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

func (c *Client) Dial(addr string, token string) error {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, &tls.Config{
		NextProtos:         []string{frontproxy.SocketProxyNextProto},
		InsecureSkipVerify: true,
	})
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
	buf.WriteByte(frontproxy.TypeOpen)
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
	case frontproxy.TypeOpenSuccess:
		return nil
	case frontproxy.TypeMessage:
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
		case frontproxy.SocketErrorCodeRequestAuth:
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
		header[0] = frontproxy.TypePacket
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
		case frontproxy.TypeMessage, frontproxy.TypePacket, frontproxy.TypePing:
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
		case frontproxy.TypePacket:
			b := make([]byte, bodySize)
			copy(b, buf[:bodySize])
			c.outCh <- b
		case frontproxy.TypeMessage:
			e, err := parseMessage(buf[:bodySize])
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}
			return e
		case frontproxy.TypePing:
			h := make([]byte, 5)
			h[0] = frontproxy.TypePong
			c.conn.SetWriteDeadline(time.Now().Add(2 * frontproxy.HeartbeatInterval))
			if _, err := c.conn.Write(h); err != nil {
				return xerrors.Errorf(": %v", err)
			}
			c.conn.SetReadDeadline(time.Now().Add(2 * frontproxy.HeartbeatInterval))
		}
	}
}

func parseMessage(buf []byte) (frontproxy.MessageError, error) {
	v, err := url.ParseQuery(string(buf))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	return frontproxy.ParseMessageError(v)
}
