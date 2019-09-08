package config

import (
	"io"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"
)

type Config struct{}

func ReadConfig(f io.Reader) (*Config, error) {
	conf := &Config{}
	if err := yaml.NewDecoder(f).Decode(conf); err != nil {
		return nil, xerrors.Errorf("config: file parse error: %v", err)
	}

	return conf, nil
}
