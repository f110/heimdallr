package netutil

import (
	"net"
	"time"

	"go.f110.dev/xerrors"
)

func WaitListen(addr string, timeout time.Duration) error {
	sleepTime := time.Duration(timeout.Milliseconds() / 10)

	retry := 0
	for {
		if retry > 10 {
			return xerrors.New("netutil: timed out")
		}

		conn, err := net.DialTimeout("tcp", addr, 10*time.Millisecond)
		if err != nil {
			retry++
			time.Sleep(sleepTime * time.Millisecond)
			continue
		}
		conn.Close()
		break
	}

	return nil
}
