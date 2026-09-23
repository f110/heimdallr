package memory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.f110.dev/heimdallr/pkg/database"
)

func TestTokenDatabase(t *testing.T) {
	db := NewTokenDatabase()

	tk, err := db.SetUser("test@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, tk.Token)

	got, err := db.FindToken(context.Background(), tk.Token)
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", got.UserId)
	assert.Empty(t, got.Token)

	tokens, err := db.AllTokens(context.Background())
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Empty(t, tokens[0].Token)

	require.NoError(t, db.DeleteToken(context.Background(), tk.Token))
	_, err = db.FindToken(context.Background(), tk.Token)
	assert.ErrorIs(t, err, database.ErrTokenNotFound)
}
