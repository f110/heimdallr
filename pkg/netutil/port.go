package netutil

import (
	"net"

	"go.f110.dev/xerrors"
)

func FindUnusedPort() (int, error) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return -1, xerrors.WithStack(err)
	}
	addr := l.Addr().(*net.TCPAddr)
	if err := l.Close(); err != nil {
		return -1, xerrors.WithStack(err)
	}

	return addr.Port, nil
}
