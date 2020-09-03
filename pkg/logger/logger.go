package logger

import (
	"context"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/config"
)

var (
	Log       *zap.Logger
	LogConfig *zap.Config
	Audit     *zap.Logger
)
var initOnce = &sync.Once{}

func Init(conf *config.Logger) error {
	var err error
	initOnce.Do(func() {
		if e := initLogger(conf); e != nil {
			err = e
			return
		}

		if e := initAuditLogger(conf); e != nil {
			err = e
			return
		}
	})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func WithRequestId(ctx context.Context) zap.Field {
	v := ctx.Value("request_id")
	switch value := v.(type) {
	case string:
		return zap.String("request_id", value)
	default:
		return zap.Skip()
	}
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
