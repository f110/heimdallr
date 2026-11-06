package mcpproxy

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/config/userconfig"
)

func newUserDir(t *testing.T) *userconfig.UserDir {
	t.Setenv("HOME", t.TempDir())
	uc, err := userconfig.New()
	require.NoError(t, err)
	return uc
}

type fakeLogin struct {
	calls     atomic.Int32
	endpoints chan string
}

func newFakeLogin() *fakeLogin {
	return &fakeLogin{endpoints: make(chan string, 10)}
}

func (f *fakeLogin) login(_ context.Context, endpoint string) (string, time.Time, error) {
	n := f.calls.Add(1)
	f.endpoints <- endpoint
	time.Sleep(10 * time.Millisecond)
	return "new-token-" + string(rune('0'+n)), time.Now().Add(time.Hour), nil
}

func TestTokenSource_Token(t *testing.T) {
	t.Run("Stored token is valid", func(t *testing.T) {
		uc := newUserDir(t)
		require.NoError(t, uc.SetToken("https://stored.example.com/token", "stored-token", time.Now().Add(time.Hour)))
		l := newFakeLogin()

		got, err := NewTokenSource(uc, "", l.login, time.Minute).Token(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "stored-token", got)
		assert.Equal(t, int32(0), l.calls.Load())
	})

	t.Run("Stored token is expired", func(t *testing.T) {
		uc := newUserDir(t)
		require.NoError(t, uc.SetToken("https://stored.example.com/token", "stored-token", time.Now().Add(-time.Hour)))
		l := newFakeLogin()

		got, err := NewTokenSource(uc, "", l.login, time.Minute).Token(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "new-token-1", got)
		assert.Equal(t, "https://stored.example.com/token", <-l.endpoints)

		stored, err := uc.GetToken()
		require.NoError(t, err)
		assert.Equal(t, "new-token-1", stored.Token)
		assert.Equal(t, "https://stored.example.com/token", stored.Endpoint)
	})

	t.Run("Server is specified", func(t *testing.T) {
		uc := newUserDir(t)
		require.NoError(t, uc.SetToken("https://stored.example.com/token", "stored-token", time.Now().Add(-time.Hour)))
		l := newFakeLogin()

		_, err := NewTokenSource(uc, "flag.example.com", l.login, time.Minute).Token(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "https://flag.example.com/token", <-l.endpoints)
	})

	t.Run("Token server is unknown", func(t *testing.T) {
		uc := newUserDir(t)
		l := newFakeLogin()

		_, err := NewTokenSource(uc, "", l.login, time.Minute).Token(context.Background())
		require.Error(t, err)
		assert.Equal(t, int32(0), l.calls.Load())
	})

	t.Run("Login timed out", func(t *testing.T) {
		uc := newUserDir(t)
		login := func(ctx context.Context, _ string) (string, time.Time, error) {
			<-ctx.Done()
			return "", time.Time{}, xerrors.WithStack(ctx.Err())
		}

		_, err := NewTokenSource(uc, "flag.example.com", login, 50*time.Millisecond).Token(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "did not complete")
	})
}

func TestTokenSource_Renew(t *testing.T) {
	t.Run("Stored token is rejected", func(t *testing.T) {
		uc := newUserDir(t)
		require.NoError(t, uc.SetToken("https://stored.example.com/token", "stored-token", time.Now().Add(time.Hour)))
		l := newFakeLogin()

		got, err := NewTokenSource(uc, "", l.login, time.Minute).Renew(context.Background(), "stored-token")
		require.NoError(t, err)
		assert.Equal(t, "new-token-1", got)
	})

	t.Run("Stored token is already renewed", func(t *testing.T) {
		uc := newUserDir(t)
		require.NoError(t, uc.SetToken("https://stored.example.com/token", "renewed-token", time.Now().Add(time.Hour)))
		l := newFakeLogin()

		got, err := NewTokenSource(uc, "", l.login, time.Minute).Renew(context.Background(), "stored-token")
		require.NoError(t, err)
		assert.Equal(t, "renewed-token", got)
		assert.Equal(t, int32(0), l.calls.Load())
	})

	t.Run("Concurrent renewals share one login", func(t *testing.T) {
		uc := newUserDir(t)
		require.NoError(t, uc.SetToken("https://stored.example.com/token", "stored-token", time.Now().Add(time.Hour)))
		l := newFakeLogin()
		s := NewTokenSource(uc, "", l.login, time.Minute)

		var wg sync.WaitGroup
		for range 5 {
			wg.Go(func() {
				got, err := s.Renew(context.Background(), "stored-token")
				assert.NoError(t, err)
				assert.Equal(t, "new-token-1", got)
			})
		}
		wg.Wait()
		assert.Equal(t, int32(1), l.calls.Load())
	})
}
