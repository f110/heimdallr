package controllerbase

import (
	"context"
	"errors"
	"log/slog"
)

func WrapRetryError(err error) error {
	return &RetryError{err: err}
}

type RetryError struct {
	err error
}

func (e *RetryError) Error() string {
	return e.err.Error()
}

func (e *RetryError) Unwrap() error {
	return e.err
}

func (e *RetryError) Is(err error) bool {
	_, ok := err.(*RetryError)
	return ok
}

func ShouldRetry(err error) bool {
	return errors.Is(err, &RetryError{})
}

func WithReconciliationId(ctx context.Context) slog.Attr {
	if ctx == nil {
		return slog.Attr{}
	}

	v := ctx.Value(ReconciliationId{})
	switch value := v.(type) {
	case string:
		return slog.String("reconcilation_id", value)
	default:
		return slog.Attr{}
	}
}
