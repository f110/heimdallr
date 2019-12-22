package logger

import (
	"github.com/f110/lagrangian-proxy/pkg/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	Log       *zap.Logger
	LogConfig *zap.Config
	Audit     *zap.Logger
)

func Init(conf *config.Logger) error {
	if err := initLogger(conf); err != nil {
		return err
	}

	if err := initAuditLogger(conf); err != nil {
		return err
	}

	return nil
}

func initLogger(conf *config.Logger) error {
	encoderConf := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	zapConf := conf.ZapConfig(encoderConf)
	l, err := zapConf.Build()
	if err != nil {
		return err
	}

	Log = l
	LogConfig = zapConf
	return nil
}

func initAuditLogger(conf *config.Logger) error {
	encoderConf := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "tag",
		CallerKey:      "",
		MessageKey:     "msg",
		StacktraceKey:  "",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	zapConf := conf.ZapConfig(encoderConf)
	l, err := zapConf.Build()
	if err != nil {
		return err
	}

	Audit = l.Named("audit")
	return nil
}
