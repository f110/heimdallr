package heim

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.f110.dev/heimdallr/pkg/config/userconfig"
)

func newUserDir(t *testing.T) *userconfig.UserDir {
	t.Setenv("HOME", t.TempDir())
	uc, err := userconfig.New()
	require.NoError(t, err)
	return uc
}

func TestPrintToken(t *testing.T) {
	t.Run("Raw", func(t *testing.T) {
		uc := newUserDir(t)
		require.NoError(t, uc.SetToken("https://example.com/token", "test-token", time.Now().Add(time.Hour)))

		buf := new(bytes.Buffer)
		require.NoError(t, printToken(buf, uc, ""))
		assert.Equal(t, "test-token\n", buf.String())
	})

	t.Run("Headers", func(t *testing.T) {
		uc := newUserDir(t)
		require.NoError(t, uc.SetToken("https://example.com/token", "test-token", time.Now().Add(time.Hour)))

		buf := new(bytes.Buffer)
		require.NoError(t, printToken(buf, uc, "headers"))
		assert.JSONEq(t, `{"Authorization":"Bearer test-token"}`, buf.String())
	})

	t.Run("Expired", func(t *testing.T) {
		uc := newUserDir(t)
		require.NoError(t, uc.SetToken("https://example.com/token", "test-token", time.Now().Add(-time.Second)))

		buf := new(bytes.Buffer)
		err := printToken(buf, uc, "headers")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "heim login example.com")
		assert.Empty(t, buf.String())
	})

	t.Run("Not found", func(t *testing.T) {
		uc := newUserDir(t)

		buf := new(bytes.Buffer)
		err := printToken(buf, uc, "headers")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "heim login")
		assert.Empty(t, buf.String())
	})

	t.Run("Unknown format", func(t *testing.T) {
		uc := newUserDir(t)
		require.NoError(t, uc.SetToken("https://example.com/token", "test-token", time.Now().Add(time.Hour)))

		buf := new(bytes.Buffer)
		require.Error(t, printToken(buf, uc, "unknown"))
		assert.Empty(t, buf.String())
	})
}
