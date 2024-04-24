package etcd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.f110.dev/heimdallr/pkg/database"
)

func TestNewTemporaryToken(t *testing.T) {
	token := NewTemporaryToken(client)
	require.NotNil(t, token)
}

func TestTemporaryToken_IssueToken(t *testing.T) {
	token := NewTemporaryToken(client)

	code, err := token.NewCode(context.Background(), "test@example.com", "ch", "plain")
	require.NoError(t, err)
	codes, err := token.AllCodes(context.Background())
	require.NoError(t, err)
	assert.Len(t, codes, 1)

	t.Run("Failed verify", func(t *testing.T) {
		t.Parallel()

		_, err = token.IssueToken(context.Background(), code.Code, "failure")
		assert.Error(t, err)
	})

	t.Run("Unknown code", func(t *testing.T) {
		t.Parallel()

		_, err = token.IssueToken(context.Background(), "unknown", "ch")
		assert.Error(t, err)
	})

	t.Run("Success", func(t *testing.T) {
		t.Parallel()

		tk, err := token.IssueToken(context.Background(), code.Code, "ch")
		require.NoError(t, err)

		assert.NotEmpty(t, tk.Token)

		got, err := token.FindToken(context.Background(), tk.Token)
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", got.UserId)
		_, err = token.FindToken(context.Background(), "unknown")
		assert.ErrorIs(t, err, database.ErrTokenNotFound)

		tokens, err := token.AllTokens(context.Background())
		require.NoError(t, err)
		assert.Len(t, tokens, 1)
	})
}

func TestTemporaryToken_DeleteCode(t *testing.T) {
	token := NewTemporaryToken(client)

	code, err := token.NewCode(context.Background(), "test@example.com", "ch", "plain")
	require.NoError(t, err)
	err = token.DeleteCode(context.Background(), code.Code)
	require.NoError(t, err)
}

func TestTemporaryToken_DeleteToken(t *testing.T) {
	token := NewTemporaryToken(client)

	s := sha256.New()
	s.Write([]byte("ch"))
	result := s.Sum(nil)
	code, err := token.NewCode(context.Background(), "test@example.com", base64.StdEncoding.EncodeToString(result), "S256")
	require.NoError(t, err)
	tk, err := token.IssueToken(context.Background(), code.Code, "ch")
	require.NoError(t, err)

	err = token.DeleteToken(context.Background(), tk.Token)
	require.NoError(t, err)
}
