package etcd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClusterDatabase(t *testing.T) {
	v, err := NewClusterDatabase(nil, client)
	require.NoError(t, err)
	require.NotNil(t, v)
	require.NotEmpty(t, v.Id())
}

func TestClusterDatabase_JoinAndLeave(t *testing.T) {
	c, err := NewClusterDatabase(nil, client)
	require.NoError(t, err)

	err = c.Join(context.Background())
	require.NoError(t, err)

	members, err := c.MemberList(context.Background())
	require.NoError(t, err)

	require.Len(t, members, 1)
	assert.NotEmpty(t, members[0].Id)

	err = c.Leave(context.Background())
	require.NoError(t, err)

	members, err = c.MemberList(context.Background())
	require.NoError(t, err)
	assert.Len(t, members, 0)
}

func TestClusterDatabase_Alive(t *testing.T) {
	c, err := NewClusterDatabase(nil, client)
	require.NoError(t, err)

	require.False(t, c.Alive())

	err = c.Join(context.Background())
	require.NoError(t, err)

	assert.True(t, c.Alive())
}
