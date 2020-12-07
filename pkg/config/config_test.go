package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
		if !ok {
			t.Fatal("expect is ok")
		}
		assert.Equal(t, "test", backend.Name)
	})

	t.Run("GetBackendByHost", func(t *testing.T) {
		t.Parallel()

		backend, ok := conf.GetBackendByHost("test.example.com:80")
		if !ok {
			t.Fatalf("expect is ok")
		}
		if backend.Name != "test" {
			t.Fatalf("unexpected backend: %s", backend.Name)
		}
	})

	t.Run("GetBackend", func(t *testing.T) {
		t.Parallel()

		backend, ok := conf.GetBackend("test")
		if !ok {
			t.Fatalf("expect is ok")
		}
		if backend.Name != "test" {
			t.Fatalf("unexpected backend: %s", backend.Name)
		}

		_, ok = conf.GetBackend("unknown")
		if ok {
			t.Fatal("expect is not ok")
		}
	})

	t.Run("GetAllBackends", func(t *testing.T) {
		t.Parallel()

		all := conf.GetAllBackends()
		if len(all) != len(backends) {
			t.Fatalf("GetAllBackends did not returned all backends")
		}
	})

	t.Run("GetAllRoles", func(t *testing.T) {
		t.Parallel()

		all := conf.GetAllRoles()
		if len(all) != len(roles)+1 {
			t.Fatalf("GetAllRoles did not returned all roles")
		}
	})

	t.Run("GetRole", func(t *testing.T) {
		t.Parallel()

		role, err := conf.GetRole("test")
		if err != nil {
			t.Fatalf("%+v", err)
		}
		if role.Name != "test" {
			t.Fatalf("unexpected role: %s", role.Name)
		}

		_, err = conf.GetRole("unknown")
		if err != ErrRoleNotFound {
			t.Errorf("expect ErrRoleNotFound: %v", err)
		}
	})

	t.Run("GetRpcPermission", func(t *testing.T) {
		t.Parallel()

		rp, ok := conf.GetRpcPermission("test")
		if !ok {
			t.Fatalf("expect is ok")
		}
		if rp.Name != "test" {
			t.Fatalf("unexpected rpc permission: %s", rp.Name)
		}

		_, ok = conf.GetRpcPermission("unknown")
		if ok {
			t.Fatal("expect is not ok")
		}
	})
}

func TestLogger_ZapConfig(t *testing.T) {
	l := &Logger{}

	c := l.ZapConfig(zapcore.EncoderConfig{})
	if c == nil {
		t.Fatal("ZapConfig must return a value")
	}
}

func TestDatastore_GetEtcdClient(t *testing.T) {
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	if err := os.Mkdir(dataDir, 0700); err != nil {
		t.Fatal(err)
	}

	clientPort, err := netutil.FindUnusedPort()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Client port: %d", clientPort)
	peerPort, err := netutil.FindUnusedPort()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Peer port: %d", peerPort)

	u := &url.URL{Scheme: "http", Host: fmt.Sprintf("localhost:%d", clientPort)}
	c := embed.NewConfig()
	c.Dir = dataDir
	c.LogLevel = "fatal"
	c.LPUrls[0].Host = fmt.Sprintf("localhost:%d", peerPort)
	c.LCUrls[0] = *u
	e, err := embed.StartEtcd(c)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	select {
	case <-e.Server.ReadyNotify():
	case <-time.After(time.Second):
		t.Fatal("Can not start etcd server within 1 second")
	}

	ds := &Datastore{
		RawUrl: fmt.Sprintf("etcd://localhost:%d", clientPort),
	}
	if err := ds.Inflate(""); err != nil {
		t.Fatal(err)
	}

	client, err := ds.GetEtcdClient(&Logger{})
	if err != nil {
		t.Fatalf("%+v", err)
	}
	if client == nil {
		t.Fatal("GetEtcdClient should return a value")
	}
}
