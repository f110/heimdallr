package logger

import (
	"bytes"

	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"k8s.io/klog"
	klogv2 "k8s.io/klog/v2"

	"go.f110.dev/heimdallr/pkg/config"
)

type levelWriter struct {
	fn func(msg string, field ...zap.Field)
}

func (w *levelWriter) Write(p []byte) (int, error) {
	s := bytes.SplitAfterN(p, []byte(" "), 6)
	w.fn(string(bytes.TrimRight(s[len(s)-1], "\n")))
	return len(p), nil
}

func OverrideKlog(conf *config.Logger) error {
	if err := Init(conf); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	l := Log.Named("klog").WithOptions(zap.AddCallerSkip(5))
	klog.SetOutputBySeverity("INFO", &levelWriter{fn: l.Info})
	klog.SetOutputBySeverity("WARNING", &levelWriter{fn: l.Warn})
	klog.SetOutputBySeverity("ERROR", &levelWriter{fn: l.Error})
	klog.SetOutputBySeverity("FATAL", &levelWriter{fn: l.Fatal})

	klogv2.SetOutputBySeverity("INFO", &levelWriter{fn: l.Info})
	klogv2.SetOutputBySeverity("WARNING", &levelWriter{fn: l.Warn})
	klogv2.SetOutputBySeverity("ERROR", &levelWriter{fn: l.Error})
	klogv2.SetOutputBySeverity("FATAL", &levelWriter{fn: l.Fatal})
	return nil
}
