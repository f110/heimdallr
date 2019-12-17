package logger

import (
	"github.com/f110/lagrangian-proxy/pkg/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	Log   *zap.Logger
	Audit *zap.Logger
)

func Init(conf *config.Logger) error {
	level := zap.InfoLevel
	switch conf.Level {
	case "debug":
		level = zap.DebugLevel
	}
	encoding := "json"
	if conf.Encoding != "" {
		encoding = conf.Encoding
	}

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

	zapConf := zap.Config{
		Level:            zap.NewAtomicLevelAt(level),
		Development:      false,
		Sampling:         nil, // disable sampling
		Encoding:         encoding,
		EncoderConfig:    encoderConf,
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}
	l, err := zapConf.Build()
	if err != nil {
		return err
	}

	Log = l

	encoderConf = zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "",
		MessageKey:     "msg",
		StacktraceKey:  "",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	zapConf = zap.Config{
		Level:            zap.NewAtomicLevelAt(zap.InfoLevel),
		Development:      false,
		Sampling:         nil, // disable sampling
		Encoding:         encoding,
		EncoderConfig:    encoderConf,
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}
	l, err = zapConf.Build()
	if err != nil {
		return err
	}

	Audit = l.Named("audit")
	return nil
}
