package logger

import (
	"context"
	"log/slog"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
)

// GRPCInterceptorLogger adapts a *slog.Logger to the grpc-middleware logging.Logger interface.
func GRPCInterceptorLogger(l *slog.Logger) logging.Logger {
	return &grpcLogger{logger: l}
}

type grpcLogger struct {
	logger *slog.Logger
}

func (g *grpcLogger) Log(lvl logging.Level, msg string) {
	ctx := context.Background()
	var level slog.Level
	switch lvl {
	case logging.DEBUG:
		level = slog.LevelDebug
	case logging.INFO:
		level = slog.LevelInfo
	case logging.WARNING:
		level = slog.LevelWarn
	case logging.ERROR:
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	g.logger.Log(ctx, level, msg)
}

func (g *grpcLogger) With(fields ...string) logging.Logger {
	attrs := make([]any, 0, len(fields)/2)
	for i := 0; i+1 < len(fields); i += 2 {
		attrs = append(attrs, slog.String(fields[i], fields[i+1]))
	}
	return &grpcLogger{logger: g.logger.With(attrs...)}
}
