package configreader

import (
	"os"
	"path/filepath"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"
)

func ReadConfig(filename string) (*config.Config, error) {
	a, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(a)

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	conf := &config.Config{}
	if err := yaml.NewDecoder(f).Decode(conf); err != nil {
		return nil, xerrors.Errorf("config: file parse error: %v", err)
	}
	if conf.General != nil {
		if err := conf.General.Inflate(dir); err != nil {
			return nil, err
		}
	}
	if conf.Datastore != nil {
		if err := conf.Datastore.Inflate(dir); err != nil {
			return nil, err
		}
	}
	if conf.FrontendProxy != nil {
		if err := conf.FrontendProxy.Inflate(dir); err != nil {
			return nil, err
		}
	}

	return conf, nil
}
