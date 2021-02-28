package etcd

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/v3/clientv3"
	"go.etcd.io/etcd/v3/mvcc/mvccpb"
	"sigs.k8s.io/yaml"

	"go.f110.dev/heimdallr/pkg/database"
)

func TestNewUserDatabase(t *testing.T) {
	u, err := NewUserDatabase(context.Background(), client, database.SystemUser)
	require.NoError(t, err)
	require.NotNil(t, u)
}

func TestUserDatabase_SetAndGetUser(t *testing.T) {
	Id := "test@example.com"
	u, err := NewUserDatabase(context.Background(), client)
	require.NoError(t, err)

	err = u.Set(context.Background(), &database.User{
		Id:    Id,
		Roles: []string{"test"},
	})
	require.NoError(t, err)
	err = u.Set(context.Background(), &database.User{
		Id:    "sa@example.com",
		Roles: []string{"test"},
		Type:  database.UserTypeServiceAccount,
	})
	require.NoError(t, err)
	err = u.Set(context.Background(), &database.User{})
	assert.Error(t, err)

	user, err := u.Get(Id)
	require.NoError(t, err)
	require.Equal(t, Id, user.Id)

	users, err := u.GetAll()
	require.NoError(t, err)
	require.Len(t, users, 2)

	sa, err := u.GetAllServiceAccount()
	require.NoError(t, err)
	require.Len(t, sa, 1)

	err = u.Delete(context.Background(), Id)
	require.NoError(t, err)

	_, err = u.Get(Id)
	require.Equal(t, database.ErrUserNotFound, err)

	u, err = NewUserDatabase(context.Background(), client)
	require.NoError(t, err)
	require.NotNil(t, u)
}

func TestUserDatabase_GetAndSetAccessToken(t *testing.T) {
	u, err := NewUserDatabase(context.Background(), client)
	require.NoError(t, err)

	err = u.SetAccessToken(context.Background(), &database.AccessToken{
		UserId: "test@example.com",
		Value:  "test-token",
	})
	require.NoError(t, err)

	token, err := u.GetAccessToken("test-token")
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", token.UserId)

	tokens, err := u.GetAccessTokens("test@example.com")
	require.NoError(t, err)
	assert.Len(t, tokens, 1)

	u, err = NewUserDatabase(context.Background(), client)
	require.NoError(t, err)
	require.NotNil(t, u)
}

func TestUserDatabase_GetAndSetState(t *testing.T) {
	u, err := NewUserDatabase(context.Background(), client)
	require.NoError(t, err)

	_, err = u.GetState(context.Background(), "")
	assert.Error(t, err)

	state, err := u.SetState(context.Background(), "unique-value")
	require.NoError(t, err)
	require.NotEmpty(t, state)

	unique, err := u.GetState(context.Background(), state)
	require.NoError(t, err)
	require.Equal(t, "unique-value", unique)

	now = func() time.Time { return time.Now().Add(24 * time.Hour) }
	defer func() { now = time.Now }()

	_, err = u.GetState(context.Background(), state)
	assert.Error(t, err)

	err = u.DeleteState(context.Background(), state)
	require.NoError(t, err)
}

func TestUserDatabase_Delete(t *testing.T) {
	u, err := NewUserDatabase(context.Background(), client)
	require.NoError(t, err)

	err = u.Set(context.Background(), &database.User{
		Id:    "test@example.com",
		Roles: []string{"test"},
	})
	require.NoError(t, err)
	err = u.Set(context.Background(), &database.User{Id: "test@example.com"})
	require.NoError(t, err)

	_, err = u.Get("test@example")
	require.Equal(t, database.ErrUserNotFound, err)
}

func TestUserDatabase_Close(t *testing.T) {
	u, err := NewUserDatabase(context.Background(), client)
	require.NoError(t, err)

	u.Close()
	_, err = u.Get("")
	assert.Equal(t, database.ErrClosed, err)
	_, err = u.GetAll()
	assert.Equal(t, database.ErrClosed, err)
	_, err = u.GetAllServiceAccount()
	assert.Equal(t, database.ErrClosed, err)
	_, err = u.GetAccessTokens("")
	assert.Equal(t, database.ErrClosed, err)
	_, err = u.GetAccessToken("")
	assert.Equal(t, database.ErrClosed, err)
}

func TestUserDatabase_WatchUser(t *testing.T) {
	u, err := NewUserDatabase(context.Background(), client)
	require.NoError(t, err)

	buf, err := database.MarshalUser(&database.User{Id: "test@example.com"})
	require.NoError(t, err)
	put := &clientv3.Event{
		Type: clientv3.EventTypePut,
		Kv:   &mvccpb.KeyValue{Value: buf},
	}
	u.watchUserEvent([]*clientv3.Event{put})

	user, err := u.Get("test@example.com")
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", user.Id)

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
	_, err = u.Get("test@example.com")
	assert.Equal(t, database.ErrUserNotFound, err)
}

func TestUserDatabase_WatchToken(t *testing.T) {
	u, err := NewUserDatabase(context.Background(), client)
	require.NoError(t, err)

	buf, err := yaml.Marshal(&database.AccessToken{Value: "test-token", UserId: "test@example.com"})
	require.NoError(t, err)
	u.watchTokenEvent([]*clientv3.Event{
		{
			Type: clientv3.EventTypePut,
			Kv:   &mvccpb.KeyValue{Value: buf},
		},
	})

	tokens, err := u.GetAccessTokens("test@example.com")
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "test-token", tokens[0].Value)

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
	_, err = u.GetAccessToken("test-token")
	assert.Equal(t, database.ErrAccessTokenNotFound, err)
}
