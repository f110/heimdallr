package rpc

import (
	"testing"
)

func TestMethodMatcher_normalize(t *testing.T) {
	m := NewMethodMatcher()
	got := m.normalize("/proxy.rpc.Admin/RevokedCertList")
	if got != "proxy.rpc.admin.revokedcertlist" {
		t.Fail()
	}

	got = m.normalize("proxy.rpc.Admin/RevokedCertList")
	if got != "proxy.rpc.admin.revokedcertlist" {
		t.Fail()
	}
}

func TestMethodMatcher_Add(t *testing.T) {
	m := NewMethodMatcher()
	err := m.Add("/proxy.rpc.admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Add("/proxy.rpc.cluster"); err != nil {
		t.Fatal(err)
	}
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
		if err := m.Add(v); err != nil {
			t.Fatal(err)
		}
	}

	for _, c := range cases {
		got := m.Match(c.Method)
		if got != c.Result {
			t.Errorf("%s is expected %v", c.Method, c.Result)
		}
	}
}
