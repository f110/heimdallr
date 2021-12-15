package logger

import (
	"github.com/go-logr/zapr"
	"golang.org/x/xerrors"
	"k8s.io/klog/v2"

	"go.f110.dev/heimdallr/pkg/config/configv2"
)

func OverrideKlog(conf *configv2.Logger) error {
	if err := Init(conf); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	klog.SetLogger(zapr.NewLogger(Log.Named("klog")))

	return nil
}
