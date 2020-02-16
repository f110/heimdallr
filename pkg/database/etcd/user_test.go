package etcd

import (
	"context"
	"testing"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/mvcc/mvccpb"
	"sigs.k8s.io/yaml"

	"github.com/f110/lagrangian-proxy/pkg/database"
)

func TestNewUserDatabase(t *testing.T) {
	u, err := NewUserDatabase(context.Background(), client, database.SystemUser)
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		t.Fatal("NewUserDatabase should return a value")
	}
}

func TestUserDatabase_SetAndGetUser(t *testing.T) {
	Id := "test@example.com"
	u, err := NewUserDatabase(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	defer clearDatabase(t)

	err = u.Set(context.Background(), &database.User{
		Id:    Id,
		Roles: []string{"test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = u.Set(context.Background(), &database.User{
		Id:    "sa@example.com",
		Roles: []string{"test"},
		Type:  database.UserTypeServiceAccount,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = u.Set(context.Background(), &database.User{})
	if err == nil {
		t.Error("Expect occurred an error")
	}

	user, err := u.Get(Id)
	if err != nil {
		t.Fatal(err)
	}
	if user.Id != Id {
		t.Fatalf("Unexpected ID: %s", user.Id)
	}

	users, err := u.GetAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("expect returning 2 users: %d users", len(users))
	}

	sa, err := u.GetAllServiceAccount()
	if err != nil {
		t.Fatal(err)
	}
	if len(sa) != 1 {
		t.Fatalf("expect returing 1 service account: %d service accounts", len(sa))
	}

	if err := u.Delete(context.Background(), Id); err != nil {
		t.Fatal(err)
	}

	if _, err := u.Get(Id); err != database.ErrUserNotFound {
		t.Fatal("expect user not found")
	}

	u, err = NewUserDatabase(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		t.Error("NewUserDatabase should return a value")
	}
}

func TestUserDatabase_GetAndSetAccessToken(t *testing.T) {
	u, err := NewUserDatabase(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	defer clearDatabase(t)

	err = u.SetAccessToken(context.Background(), &database.AccessToken{
		UserId: "test@example.com",
		Value:  "test-token",
	})
	if err != nil {
		t.Fatal(err)
	}

	token, err := u.GetAccessToken("test-token")
	if err != nil {
		t.Fatal(err)
	}
	if token.UserId != "test@example.com" {
		t.Errorf("token was returned but unexpected value: %s", token.UserId)
	}

	tokens, err := u.GetAccessTokens("test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 {
		t.Errorf("Expect returning 1 token: %d tokens", len(tokens))
	}

	u, err = NewUserDatabase(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if u == nil {
		t.Fatal("NewUserDatabase should return a value")
	}
}

func TestUserDatabase_GetAndSetState(t *testing.T) {
	u, err := NewUserDatabase(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	defer clearDatabase(t)

	if _, err := u.GetState(context.Background(), ""); err == nil {
		t.Error("Expect occurred an error")
	}

	state, err := u.SetState(context.Background(), "unique-value")
	if err != nil {
		t.Fatal(err)
	}
	if state == "" {
		t.Fatal("SetState should return a value")
	}

	unique, err := u.GetState(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if unique != "unique-value" {
		t.Fatal("Unexpected unique value")
	}

	now = func() time.Time { return time.Now().Add(24 * time.Hour) }
	defer func() { now = time.Now }()

	_, err = u.GetState(context.Background(), state)
	if err == nil {
		t.Error("Expect occurred an error")
	}

	if err := u.DeleteState(context.Background(), state); err != nil {
		t.Fatal(err)
	}
}

func TestUserDatabase_Delete(t *testing.T) {
	u, err := NewUserDatabase(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	defer clearDatabase(t)

	err = u.Set(context.Background(), &database.User{
		Id:    "test@example.com",
		Roles: []string{"test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = u.Set(context.Background(), &database.User{Id: "test@example.com"})
	if err != nil {
		t.Fatal(err)
	}

	_, err = u.Get("test@example")
	if err != database.ErrUserNotFound {
		t.Fatal("Expect occurred ErrUserNotFound")
	}
}

func TestUserDatabase_Close(t *testing.T) {
	u, err := NewUserDatabase(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}

	u.Close()
	if _, err := u.Get(""); err != database.ErrClosed {
		t.Error("Expect occurred ErrClosed")
	}
	if _, err := u.GetAll(); err != database.ErrClosed {
		t.Error("Expect occurred ErrClosed")
	}
	if _, err := u.GetAllServiceAccount(); err != database.ErrClosed {
		t.Error("Expect occurred ErrClosed")
	}
	if _, err := u.GetAccessTokens(""); err != database.ErrClosed {
		t.Error("Expect occurred ErrClosed")
	}
	if _, err := u.GetAccessToken(""); err != database.ErrClosed {
		t.Error("Expect occurred ErrClosed")
	}
}

func TestUserDatabase_WatchUser(t *testing.T) {
	u, err := NewUserDatabase(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}

	buf, err := database.MarshalUser(&database.User{Id: "test@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	put := &clientv3.Event{
		Type: clientv3.EventTypePut,
		Kv:   &mvccpb.KeyValue{Value: buf},
	}
	u.watchUserEvent([]*clientv3.Event{put})

	user, err := u.Get("test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if user.Id != "test@example.com" {
		t.Error("Unexpected user")
	}

	u.watchUserEvent([]*clientv3.Event{
		{
			Type: clientv3.EventTypeDelete,
			Kv: &mvccpb.KeyValue{
				Key: []byte("/test@example.com"),
			},
		},
		{
			Type: clientv3.EventTypeDelete,
			Kv: &mvccpb.KeyValue{
				Key: []byte("/unknown@example.com"),
			},
		},
	})
	if _, err := u.Get("test@example.com"); err != database.ErrUserNotFound {
		t.Error("Expect ErrUserNotFound")
	}
}

func TestUserDatabase_WatchToken(t *testing.T) {
	u, err := NewUserDatabase(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}

	buf, err := yaml.Marshal(&database.AccessToken{Value: "test-token", UserId: "test@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	u.watchTokenEvent([]*clientv3.Event{
		{
			Type: clientv3.EventTypePut,
			Kv:   &mvccpb.KeyValue{Value: buf},
		},
	})

	tokens, err := u.GetAccessTokens("test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 {
		t.Errorf("Expect returning 1 token: %d tokens", len(tokens))
	}
	if tokens[0].Value != "test-token" {
		t.Errorf("Unexpected token value")
	}

	u.watchTokenEvent([]*clientv3.Event{
		{
			Type: clientv3.EventTypeDelete,
			Kv:   &mvccpb.KeyValue{Key: []byte("/test-token")},
		},
		{
			Type: clientv3.EventTypeDelete,
			Kv:   &mvccpb.KeyValue{Key: []byte("/unknown")},
		},
	})
	if _, err := u.GetAccessToken("test-token"); err != database.ErrAccessTokenNotFound {
		t.Error("Expected ErrAccessTokenNotFound")
	}
}
