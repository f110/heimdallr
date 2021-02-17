package logger

import (
	"context"
	"reflect"
	"sync"

	"github.com/spf13/pflag"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/config/configv2"
)

var (
	Log       *zap.Logger
	LogConfig *zap.Config
	Audit     *zap.Logger
	flagConf  configv2.Logger
)
var initOnce = &sync.Once{}

func Init(conf *configv2.Logger) error {
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

// InitByFlags constructs the logger.
// The logger configuration will bring from command line arguments.
// Thus, you must define the flag by Flags and parse arguments before calling this.
func InitByFlags() error {
	var err error
	initOnce.Do(func() {
		if e := initLogger(&flagConf); e != nil {
			err = e
			return
		}
		if e := initAuditLogger(&flagConf); e != nil {
			err = e
			return
		}
	})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func Flags(fs *pflag.FlagSet) {
	fs.StringVar(&flagConf.Level, "log-level", "info", "Log level")
	fs.StringVar(&flagConf.Encoding, "log-encoding", "json", "Log encoding (json or console)")
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

// TypeOf constructs a field of zap. value will be convert to type name.
func TypeOf(key string, val interface{}) zap.Field {
	return zap.String(key, reflect.TypeOf(val).String())
}

func initLogger(conf *configv2.Logger) error {
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

func initAuditLogger(conf *configv2.Logger) error {
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
