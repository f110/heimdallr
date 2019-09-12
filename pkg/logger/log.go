package logger

import (
	"bytes"
	"log"
	"os"
)

var (
	LogCompatible *log.Logger
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
	LogCompatible = log.New(&msgWriter{}, "", log.LstdFlags)
}
