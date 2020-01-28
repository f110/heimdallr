package config

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/coreos/etcd/embed"
	"go.uber.org/zap/zapcore"
)

func TestGeneral(t *testing.T) {
	conf := &General{
		ServerNameHost: "example.com",
	}
	backends := []*Backend{
		{Name: "test"},
	}
	roles := []*Role{
		{Name: "test"},
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
		if backend.Name != "test" {
			t.Fatalf("unexpected backend: %s", backend.Name)
		}
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
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	c := embed.NewConfig()
	c.Dir = tmpDir
	c.LogPkgLevels = "*=C"
	c.SetupLogging()
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
		RawUrl: "etcd://localhost:2379",
	}
	if err := ds.Inflate(""); err != nil {
		t.Fatal(err)
	}

	client, err := ds.GetEtcdClient(&Logger{})
	if err != nil {
		t.Fatalf("%+v", err)
	}
	_ = client
}
