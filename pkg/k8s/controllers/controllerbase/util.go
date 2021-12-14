package controllerbase

import (
	"context"
	"errors"

	"go.uber.org/zap"
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

func WithReconciliationId(ctx context.Context) zap.Field {
	if ctx == nil {
		return zap.Skip()
	}

	v := ctx.Value(ReconciliationId{})
	switch value := v.(type) {
	case string:
		return zap.String("reconcilation_id", value)
	default:
		return zap.Skip()
	}
}
