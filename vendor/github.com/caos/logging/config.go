package logging

import (
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
)

type Config struct {
	Level       string    `json:"level"`
	Formatter   formatter `json:"formatter"`
	LocalLogger bool      `json:"localLogger"`
	LogCaller   bool      `json:"logCaller"`
}

type formatter struct {
	Format string                 `json:"format"`
	Data   map[string]interface{} `json:"data"`
}

type loggingConfig Config

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	log = (*logger)(logrus.New())
	err := unmarshal((*loggingConfig)(c))
	if err != nil {
		return err
	}
	return c.unmarshal()
}

func (c *Config) UnmarshalJSON(data []byte) error {
	log = (*logger)(logrus.New())
	err := json.Unmarshal(data, (*loggingConfig)(c))
	if err != nil {
		return err
	}
	return c.unmarshal()
}

func (c *Config) unmarshal() (err error) {
	err = c.parseFormatter()
	if err != nil {
		return err
	}
	err = c.parseLevel()
	if err != nil {
		return err
	}
	err = c.unmarshalFormatter()
	if err != nil {
		return err
	}
	log.ReportCaller = c.LogCaller
	c.setGlobal()
	return nil
}

func (c *Config) setGlobal() {
	if c.LocalLogger {
		return
	}
	logrus.SetFormatter(log.Formatter)
	logrus.SetLevel(log.Level)
	logrus.SetReportCaller(log.ReportCaller)
	log = (*logger)(logrus.StandardLogger())
}

func (c *Config) unmarshalFormatter() error {
	formatterData, err := json.Marshal(c.Formatter.Data)
	if err != nil {
		return err
	}
	return json.Unmarshal(formatterData, log.Formatter)
}

func (c *Config) parseLevel() error {
	if c.Level == "" {
		log.Level = logrus.InfoLevel
		return nil
	}
	level, err := logrus.ParseLevel(c.Level)
	if err != nil {
		return err
	}
	log.Level = level
	return nil
}

func (c *Config) parseFormatter() error {
	switch c.Formatter.Format {
	case "json":
		log.Formatter = &logrus.JSONFormatter{}
	case "text", "":
		log.Formatter = &logrus.TextFormatter{}
	default:
		return fmt.Errorf("%s formatter not supported", c.Formatter)
	}
	return nil
}
