package framework

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStack(t *testing.T) {
	st := newStack()
	require.True(t, st.isEmpty())

	st.push("1")
	st.push("2")
	require.False(t, st.isEmpty())
	require.Equal(t, "2", st.pop().(string))
	require.Equal(t, "1", st.pop().(string))
	require.True(t, st.isEmpty())

	st.push("3")
	require.Equal(t, "3", st.pop().(string))
}
