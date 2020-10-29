package logger

import (
	"bytes"

	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"k8s.io/klog/v2"

	"go.f110.dev/heimdallr/pkg/config/configv2"
)

type levelWriter struct {
	fn func(msg string, field ...zap.Field)
}

func (w *levelWriter) Write(p []byte) (int, error) {
	s := bytes.SplitAfterN(p, []byte(" "), 6)
	w.fn(string(bytes.TrimRight(s[len(s)-1], "\n")))
	return len(p), nil
}

func OverrideKlog(conf *configv2.Logger) error {
	if err := Init(conf); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	l := Log.Named("klog").WithOptions(zap.AddCallerSkip(5))
	klog.SetOutputBySeverity("INFO", &levelWriter{fn: l.Info})
	klog.SetOutputBySeverity("WARNING", &levelWriter{fn: l.Info})
	klog.SetOutputBySeverity("ERROR", &levelWriter{fn: l.Info})
	klog.SetOutputBySeverity("FATAL", &levelWriter{fn: l.Info})
	return nil
}
