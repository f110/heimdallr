package netutil

import (
	"net"

	"golang.org/x/xerrors"
)

func FindUnusedPort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return -1, xerrors.Errorf(": %v", err)
	}
	addr := l.Addr().(*net.TCPAddr)
	if err := l.Close(); err != nil {
		return -1, xerrors.Errorf(": %v", err)
	}

	return addr.Port, nil
}
