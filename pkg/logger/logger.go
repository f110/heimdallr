package logger

import (
	"context"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/spf13/pflag"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/config/configv2"
)

var (
	Log      *slog.Logger
	Audit    *slog.Logger
	flagConf configv2.Logger
)
var initOnce = &sync.Once{}

func Init(conf *configv2.Logger) error {
	initOnce.Do(func() {
		Log = newLogger(conf)
		Audit = newLogger(conf).With(slog.String("tag", "audit"))
	})
	return nil
}

// InitByFlags constructs the logger.
// The logger configuration will bring from command line arguments.
// Thus, you must define the flag by Flags and parse arguments before calling this.
func InitByFlags() error {
	return Init(&flagConf)
}

type flagSet interface {
	*pflag.FlagSet | *cmd.FlagSet
}

func Flags[FS flagSet](v FS) {
	switch fs := any(v).(type) {
	case *pflag.FlagSet:
		fs.StringVar(&flagConf.Level, "log-level", "info", "Log level")
		fs.StringVar(&flagConf.Encoding, "log-encoding", "json", "Log encoding (json or console)")
	case *cmd.FlagSet:
		fs.String("log-level", "Log level").Var(&flagConf.Level).Default("info")
		fs.String("log-encoding", "Log encoding (json or console)").Var(&flagConf.Encoding).Default("json")
	}
}

func WithRequestId(ctx context.Context) slog.Attr {
	v := ctx.Value("request_id")
	switch value := v.(type) {
	case string:
		return slog.String("request_id", value)
	default:
		return slog.Attr{}
	}
}

// TypeOf constructs an attribute. value will be converted to type name.
func TypeOf(key string, val interface{}) slog.Attr {
	return slog.String(key, reflect.TypeOf(val).String())
}

func newLogger(conf *configv2.Logger) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(conf.Level)}

	encoding := strings.ToLower(conf.Encoding)
	if encoding == "" {
		encoding = "json"
	}
	var handler slog.Handler
	switch encoding {
	case "console":
		handler = slog.NewTextHandler(os.Stdout, opts)
	default:
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error", "panic", "fatal":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
