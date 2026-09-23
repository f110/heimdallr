package userconfig

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newUserDir(t *testing.T) (*UserDir, string) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	c, err := New()
	require.NoError(t, err)

	return c, tmpDir
}

func TestUserDir_GetToken(t *testing.T) {
	t.Run("JSON", func(t *testing.T) {
		c, home := newUserDir(t)
		require.NoError(t, os.Mkdir(filepath.Join(home, Directory), 0755))
		err := os.WriteFile(
			filepath.Join(home, Directory, TokenFilename),
			[]byte(`{"endpoint":"https://example.com/token","token":"test-token","expires_at":"2026-01-02T03:04:05Z"}`),
			0600,
		)
		require.NoError(t, err)

		gotToken, err := c.GetToken()
		require.NoError(t, err)
		assert.Equal(t, &Token{
			Endpoint:  "https://example.com/token",
			Token:     "test-token",
			ExpiresAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		}, gotToken)
	})

	t.Run("Legacy format", func(t *testing.T) {
		c, home := newUserDir(t)
		require.NoError(t, os.Mkdir(filepath.Join(home, Directory), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(home, Directory, TokenFilename), []byte("test-token"), 0600))

		gotToken, err := c.GetToken()
		require.NoError(t, err)
		assert.Nil(t, gotToken)
	})

	t.Run("Not found", func(t *testing.T) {
		c, _ := newUserDir(t)

		gotToken, err := c.GetToken()
		require.NoError(t, err)
		assert.Nil(t, gotToken)
	})
}

func TestUserDir_SetToken(t *testing.T) {
	c, _ := newUserDir(t)

	expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)
	require.NoError(t, c.SetToken("https://example.com/token", "test-token", expiresAt))

	gotToken, err := c.GetToken()
	require.NoError(t, err)
	assert.True(t, expiresAt.Equal(gotToken.ExpiresAt))
	assert.Equal(t, "https://example.com/token", gotToken.Endpoint)
	assert.Equal(t, "test-token", gotToken.Token)
}

func TestToken_IsExpired(t *testing.T) {
	var nilToken *Token
	assert.True(t, nilToken.IsExpired())
	assert.True(t, (&Token{Token: "test", ExpiresAt: time.Now().Add(-time.Second)}).IsExpired())
	assert.True(t, (&Token{ExpiresAt: time.Now().Add(time.Hour)}).IsExpired())
	assert.False(t, (&Token{Token: "test", ExpiresAt: time.Now().Add(time.Hour)}).IsExpired())
}
