package config

import (
	"testing"
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
