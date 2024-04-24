package btesting

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/netutil"
)

type MockServer struct {
	Port int

	server      *http.Server
	gotRequests []*http.Request
}

func NewMockServer() (*MockServer, error) {
	port, err := netutil.FindUnusedPort()
	if err != nil {
		return nil, err
	}

	return &MockServer{Port: port}, nil
}

func (s *MockServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		s.gotRequests = append(s.gotRequests, req)
	})
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", s.Port),
		Handler: mux,
	}
	s.server = server
	go server.ListenAndServe()

	return nil
}

func (s *MockServer) Stop() error {
	return s.server.Shutdown(context.Background())
}

func (s *MockServer) Requests() []*http.Request {
	return s.gotRequests
}

type MockTCPServer struct {
	Port int

	listener net.Listener

	mu         sync.Mutex
	activeConn map[string]net.Conn
}

func NewMockTCPServer() (*MockTCPServer, error) {
	port, err := netutil.FindUnusedPort()
	if err != nil {
		return nil, err
	}

	return &MockTCPServer{Port: port, activeConn: make(map[string]net.Conn)}, nil
}

func (s *MockTCPServer) Start() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.Port))
	if err != nil {
		return xerrors.WithStack(err)
	}

	s.listener = lis
	go func() {
		for {
			conn, err := s.listener.Accept()
			if errors.Is(err, net.ErrClosed) {
				break
			}
			if err != nil {
				log.Printf("Error accept new conn: %v", err)
				continue
			}
			go s.accept(conn)
		}
	}()

	return nil
}

func (s *MockTCPServer) Stop() error {
	if s.listener == nil {
		return nil
	}

	s.mu.Lock()
	conns := make([]net.Conn, 0)
	for _, conn := range s.activeConn {
		conns = append(conns, conn)
	}
	s.mu.Unlock()
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			log.Printf("Failed close connection of %s: %v", conn.RemoteAddr().String(), err)
		}
	}

	return s.listener.Close()
}

func (s *MockTCPServer) accept(conn net.Conn) {
	s.mu.Lock()
	s.activeConn[conn.RemoteAddr().String()] = conn
	s.mu.Unlock()

	conn.Write([]byte("HELLO"))

	buf := make([]byte, 1024)
	for {
		_, err := conn.Read(buf)
		if err == io.EOF {
			break
		} else if err != nil {
			break
		}
	}

	s.mu.Lock()
	delete(s.activeConn, conn.RemoteAddr().String())
	s.mu.Unlock()
}
