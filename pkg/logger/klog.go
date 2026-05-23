package logger

import (
	"log/slog"

	"k8s.io/klog/v2"
)

func OverrideKlog() error {
	klog.SetSlogLogger(Log.With(slog.String("logger", "klog")))
	return nil
}
