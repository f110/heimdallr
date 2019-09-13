package logger

import (
	"bytes"
	"log"
	"os"
)

var (
	CompatibleLogger *log.Logger
)

type msgWriter struct{}

func (m *msgWriter) Write(p []byte) (int, error) {
	if Log != nil {
		Log.Debug(string(bytes.TrimRight(p, "\n")))
		return len(p), nil
	} else {
		return os.Stderr.Write(p)
	}
}

func init() {
	CompatibleLogger = log.New(&msgWriter{}, "", 0)
}
