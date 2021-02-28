package rpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMethodMatcher_normalize(t *testing.T) {
	m := NewMethodMatcher()
	got := m.normalize("/proxy.rpc.Admin/RevokedCertList")
	require.Equal(t, "proxy.rpc.admin.revokedcertlist", got)

	got = m.normalize("proxy.rpc.Admin/RevokedCertList")
	require.Equal(t, "proxy.rpc.admin.revokedcertlist", got)
}

func TestMethodMatcher_Add(t *testing.T) {
	m := NewMethodMatcher()
	err := m.Add("/proxy.rpc.admin")
	require.NoError(t, err)
	err = m.Add("/proxy.rpc.cluster")
	require.NoError(t, err)
}

func TestMethodMatcher_Match(t *testing.T) {
	allowRules := []string{
		"/proxy.rpc.Admin/UserAdd",
		"/proxy.rpc.Cluster/*",
	}
	cases := []struct {
		Method string
		Result bool
	}{
		{"/proxy.rpc.Admin/UserAdd", true},
		{"/proxy.rpc.Admin/UserDel", false},
		{"/proxy.rpc.Cluster/MemberList", true},
		{"/proxy.rpc.Admin/MemberList", false},
	}
	m := NewMethodMatcher()
	for _, v := range allowRules {
		err := m.Add(v)
		require.NoError(t, err)
	}

	for _, c := range cases {
		got := m.Match(c.Method)
		assert.Equal(t, c.Result, got)
	}
}
