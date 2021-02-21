package userconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserDir_GetToken(t *testing.T) {
	tmpDir := t.TempDir()

	err := os.Mkdir(filepath.Join(tmpDir, Directory), 0755)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, Directory, "token"), []byte("test-token"), 0644)
	require.NoError(t, err)

	prevHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer func() {
		os.Setenv("HOME", prevHome)
	}()
	c, err := New()
	require.NoError(t, err)
	gotToken, err := c.GetToken()
	require.NoError(t, err)

	assert.Equal(t, "test-token", gotToken)
}
