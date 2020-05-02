package etcd

import (
	"context"
	"testing"
)

func TestNewClusterDatabase(t *testing.T) {
	v, err := NewClusterDatabase(nil, client)
	if err != nil {
		t.Fatal(err)
	}
	if v == nil {
		t.Fatal("NewClusterDatabase should return a value")
	}
	if v.Id() == "" {
		t.Fatal("Id should return something")
	}
}

func TestClusterDatabase_JoinAndLeave(t *testing.T) {
	c, err := NewClusterDatabase(nil, client)
	if err != nil {
		t.Fatal(err)
	}
	defer clearDatabase(t)

	if err := c.Join(context.Background()); err != nil {
		t.Fatal(err)
	}

	members, err := c.MemberList(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(members) != 1 {
		t.Fatal("I should be a member")
	}
	if members[0].Id == "" {
		t.Error("Member.Id is an empty string")
	}

	if err := c.Leave(context.Background()); err != nil {
		t.Fatal(err)
	}

	members, err = c.MemberList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 0 {
		t.Fatal("I should not be a member")
	}
}

func TestClusterDatabase_Alive(t *testing.T) {
	c, err := NewClusterDatabase(nil, client)
	if err != nil {
		t.Fatal(err)
	}
	defer clearDatabase(t)

	if c.Alive() {
		t.Fatal("should not alive because not joined yet")
	}

	if err := c.Join(context.Background()); err != nil {
		t.Fatal(err)
	}

	if !c.Alive() {
		t.Fatal("should alive because already joined")
	}
}
