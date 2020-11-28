package configutil

import (
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/k8s"
	"go.f110.dev/heimdallr/pkg/logger"
)

type Reloader struct {
	certWatcher   *k8s.VolumeWatcher
	configWatcher *k8s.VolumeWatcher
}

func NewReloader(conf *configv2.Config) (*Reloader, error) {
	r := &Reloader{}
	if conf.AccessProxy.HTTP.Certificate != nil && k8s.CanWatchVolume(conf.AccessProxy.HTTP.Certificate.CertFile) {
		mountPath, err := k8s.FindMountPath(conf.AccessProxy.HTTP.Certificate.CertFile)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		w, err := k8s.NewVolumeWatcher(mountPath, func() {
			logger.Log.Info("Reload certificate")
			if err := conf.AccessProxy.HTTP.Certificate.ReloadCertificate(); err != nil {
				logger.Log.Error("Failed reload certificate", zap.Error(err))
			}
		})
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		r.certWatcher = w
	}
	if k8s.CanWatchVolume(conf.AccessProxy.ProxyFile) ||
		k8s.CanWatchVolume(conf.AuthorizationEngine.RoleFile) ||
		k8s.CanWatchVolume(conf.AuthorizationEngine.RPCPermissionFile) {
		mountPath, err := k8s.FindMountPath(conf.AccessProxy.ProxyFile)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		w, err := k8s.NewVolumeWatcher(mountPath, func() {
			if err := conf.AccessProxy.ReloadConfig(); err != nil {
				logger.Log.Error("Failed reload proxy config", zap.Error(err))
			}
			if err := conf.AuthorizationEngine.ReloadConfig(); err != nil {
				logger.Log.Error("Failed reload authorization engine config", zap.Error(err))
			}
		})
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		r.configWatcher = w
	}

	return r, nil
}

func (r *Reloader) Stop() {
	r.certWatcher.Stop()
	r.configWatcher.Stop()
}
