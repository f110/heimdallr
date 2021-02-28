package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/v3/embed"
	"go.uber.org/zap/zapcore"

	"go.f110.dev/heimdallr/pkg/netutil"
)

func TestGeneral(t *testing.T) {
	conf := &General{
		ServerNameHost: "example.com",
	}
	backends := []*Backend{
		{Name: "test"},
		{Name: "AgentAndSocket", Agent: true, Socket: true},
	}
	roles := []*Role{
		{Name: "test"},
		{Name: "test2", Bindings: []*Binding{{Backend: "missing"}}},
	}
	rpcPermissions := []*RpcPermission{
		{Name: "test"},
	}
	if err := conf.Load(backends, roles, rpcPermissions); err != nil {
		t.Fatalf("%+v", err)
	}

	t.Run("GetBackendByHostname", func(t *testing.T) {
		t.Parallel()

		backend, ok := conf.GetBackendByHostname("test.example.com")
		require.True(t, ok)
		assert.Equal(t, "test", backend.Name)
	})

	t.Run("GetBackendByHost", func(t *testing.T) {
		t.Parallel()

		backend, ok := conf.GetBackendByHost("test.example.com:80")
		require.True(t, ok)
		assert.Equal(t, "test", backend.Name)
	})

	t.Run("GetBackend", func(t *testing.T) {
		t.Parallel()

		backend, ok := conf.GetBackend("test")
		require.True(t, ok)
		require.Equal(t, "test", backend.Name)

		_, ok = conf.GetBackend("unknown")
		require.False(t, ok)
	})

	t.Run("GetAllBackends", func(t *testing.T) {
		t.Parallel()

		all := conf.GetAllBackends()
		assert.Equal(t, len(all), len(backends))
	})

	t.Run("GetAllRoles", func(t *testing.T) {
		t.Parallel()

		all := conf.GetAllRoles()
		assert.Equal(t, len(all), len(roles)+1)
	})

	t.Run("GetRole", func(t *testing.T) {
		t.Parallel()

		role, err := conf.GetRole("test")
		require.NoError(t, err)
		assert.Equal(t, "test", role.Name)

		_, err = conf.GetRole("unknown")
		assert.Equal(t, ErrRoleNotFound, err)
	})

	t.Run("GetRpcPermission", func(t *testing.T) {
		t.Parallel()

		rp, ok := conf.GetRpcPermission("test")
		require.True(t, ok)
		assert.Equal(t, "test", rp.Name)

		_, ok = conf.GetRpcPermission("unknown")
		require.False(t, ok)
	})
}

func TestLogger_ZapConfig(t *testing.T) {
	l := &Logger{}

	c := l.ZapConfig(zapcore.EncoderConfig{})
	require.NotNil(t, c)
}

func TestDatastore_GetEtcdClient(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	err := os.Mkdir(dataDir, 0700)
	require.NoError(t, err)

	clientPort, err := netutil.FindUnusedPort()
	require.NoError(t, err)
	t.Logf("Client port: %d", clientPort)
	peerPort, err := netutil.FindUnusedPort()
	require.NoError(t, err)
	t.Logf("Peer port: %d", peerPort)

	u := &url.URL{Scheme: "http", Host: fmt.Sprintf("localhost:%d", clientPort)}
	c := embed.NewConfig()
	c.Dir = dataDir
	c.LogLevel = "fatal"
	c.LPUrls[0].Host = fmt.Sprintf("localhost:%d", peerPort)
	c.LCUrls[0] = *u
	e, err := embed.StartEtcd(c)
	require.NoError(t, err)
	defer e.Close()

	select {
	case <-e.Server.ReadyNotify():
	case <-time.After(time.Second):
		require.Fail(t, "Can not start etcd server within 1 second")
	}

	ds := &Datastore{
		RawUrl: fmt.Sprintf("etcd://localhost:%d", clientPort),
	}
	err = ds.Inflate("")
	require.NoError(t, err)

	client, err := ds.GetEtcdClient(&Logger{})
	require.NoError(t, err)
	assert.NotNil(t, client)
}
