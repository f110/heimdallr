package logger

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
)

// GRPCInterceptorLogger adapts a *slog.Logger to the grpc-middleware logging.Logger interface.
//
// logging.Level shares the same numeric values as slog.Level, and fields are the same
// alternating key/value sequence that slog expects, so both can be forwarded as-is.
func GRPCInterceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		l.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}
