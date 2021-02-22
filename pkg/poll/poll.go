package poll

import (
	"context"
	"errors"
	"time"

	"golang.org/x/xerrors"
)

var (
	ErrTimedOut = errors.New("poll: timed out")
)

type Func func(ctx context.Context) (done bool, err error)

func Poll(ctx context.Context, interval, timeout time.Duration, fn Func) error {
	tick := time.NewTicker(interval)
	defer tick.Stop()

	limit := time.After(timeout)
	for {
		select {
		case <-tick.C:
			fnCtx, cancel := context.WithTimeout(ctx, interval)
			done, err := fn(fnCtx)
			cancel()
			if err != nil {
				return xerrors.Errorf(": %w", err)
			}
			if done {
				return nil
			}
		case <-limit:
			return ErrTimedOut
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func PollImmediate(ctx context.Context, interval, timeout time.Duration, fn Func) error {
	fnCtx, cancel := context.WithTimeout(ctx, interval)
	done, err := fn(fnCtx)
	cancel()
	if done {
		return nil
	}
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return Poll(ctx, interval, timeout, fn)
}
