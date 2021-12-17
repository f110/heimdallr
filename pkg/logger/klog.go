package logger

import (
	"github.com/go-logr/zapr"
	"k8s.io/klog/v2"
)

func OverrideKlog() error {
	klog.SetLogger(zapr.NewLogger(Log.Named("klog")))

	return nil
}
