package poll

import (
	"context"
	"time"

	"go.f110.dev/xerrors"
)

var (
	ErrTimedOut = xerrors.New("poll: timed out")
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
				return err
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
		return err
	}

	return Poll(ctx, interval, timeout, fn)
}
