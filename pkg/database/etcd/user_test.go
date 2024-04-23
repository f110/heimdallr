package etcd

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	notify := u.cache.Notify()

	err = u.Set(context.Background(), &database.User{
		Id:    Id,
		Roles: []string{"test"},
	})
	require.NoError(t, err)
	waitNotify(t, notify)
	err = u.Set(context.Background(), &database.User{
		Id:    "sa@example.com",
		Roles: []string{"test"},
		Type:  database.UserTypeServiceAccount,
	})
	require.NoError(t, err)
	err = u.Set(context.Background(), &database.User{})
	assert.Error(t, err)
	waitNotify(t, notify)

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
	waitNotify(t, notify)

	_, err = u.Get(Id)
	require.ErrorIs(t, err, database.ErrUserNotFound)

	u, err = NewUserDatabase(context.Background(), client)
	require.NoError(t, err)
	require.NotNil(t, u)
}

func TestUserDatabase_GetAndSetAccessToken(t *testing.T) {
	u, err := NewUserDatabase(context.Background(), client)
	require.NoError(t, err)
	notify := u.tokenCache.Notify()

	err = u.SetAccessToken(context.Background(), &database.AccessToken{
		UserId: "test@example.com",
		Value:  "test-token",
	})
	require.NoError(t, err)
	waitNotify(t, notify)

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
	notify := u.cache.Notify()

	err = u.Set(context.Background(), &database.User{
		Id:    "test@example.com",
		Roles: []string{"test"},
	})
	require.NoError(t, err)
	err = u.Set(context.Background(), &database.User{Id: "test@example.com"})
	require.NoError(t, err)
	waitNotify(t, notify)

	_, err = u.Get("test@example")
	require.ErrorIs(t, err, database.ErrUserNotFound)
}

func TestUserDatabase_Close(t *testing.T) {
	u, err := NewUserDatabase(context.Background(), client)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = u.cache.WaitForSync(ctx)
	require.NoError(t, err)
	err = u.tokenCache.WaitForSync(ctx)
	require.NoError(t, err)

	u.Close()
	time.Sleep(time.Second)
	_, err = u.Get("")
	assert.ErrorIs(t, err, database.ErrClosed)
	_, err = u.GetAll()
	assert.ErrorIs(t, err, database.ErrClosed)
	_, err = u.GetAllServiceAccount()
	assert.ErrorIs(t, err, database.ErrClosed)
	_, err = u.GetAccessTokens("")
	assert.ErrorIs(t, err, database.ErrClosed)
	_, err = u.GetAccessToken("")
	assert.ErrorIs(t, err, database.ErrClosed)
}
