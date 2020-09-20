package mysql

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/database/mysql/dao"
	"go.f110.dev/heimdallr/pkg/database/mysql/entity"
)

type UserDatabase struct {
	dao         *dao.Repository
	systemUsers map[string]*database.User
}

var _ database.UserDatabase = &UserDatabase{}

func NewUserDatabase(dao *dao.Repository, systemUsers ...*database.User) *UserDatabase {
	m := make(map[string]*database.User)
	for _, v := range systemUsers {
		m[v.Id] = v
	}
	return &UserDatabase{dao: dao, systemUsers: m}
}

func (u *UserDatabase) Get(id string) (*database.User, error) {
	if v, ok := u.systemUsers[id]; ok {
		return v, nil
	}

	user, err := u.dao.User.SelectIdentity(context.TODO(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, database.ErrUserNotFound
		}

		return nil, xerrors.Errorf(": %w", err)
	}
	roles, err := u.dao.RoleBinding.ListUser(context.TODO(), user.Id)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	r := make([]string, 0)
	mr := make(map[string]bool)
	for _, v := range roles {
		if v.Maintainer {
			mr[v.Role] = true
		}
		r = append(r, v.Role)
	}

	return &database.User{
		Id:            user.Identity,
		Roles:         r,
		MaintainRoles: mr,
		Admin:         user.Admin,
		Type:          user.Type,
		Comment:       user.Comment,
	}, nil
}

func (u *UserDatabase) GetAll() ([]*database.User, error) {
	users, err := u.dao.User.ListAll(context.TODO())
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	roles, err := u.dao.RoleBinding.ListAll(context.TODO())
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	roleMap := make(map[int32][]*entity.RoleBinding)
	for _, v := range roles {
		if _, ok := roleMap[v.UserId]; !ok {
			roleMap[v.UserId] = make([]*entity.RoleBinding, 0)
		}
		roleMap[v.UserId] = append(roleMap[v.UserId], v)
	}

	result := make([]*database.User, len(users))
	for i, v := range users {
		r := make([]string, 0)
		mr := make(map[string]bool)
		for _, v := range roleMap[v.Id] {
			if v.Maintainer {
				mr[v.Role] = true
			}
			r = append(r, v.Role)
		}

		result[i] = &database.User{
			Id:            v.Identity,
			Roles:         r,
			MaintainRoles: mr,
			Admin:         v.Admin,
			Type:          v.Type,
			Comment:       v.Comment,
		}
	}

	return result, nil
}

func (u *UserDatabase) GetAllServiceAccount() ([]*database.User, error) {
	users, err := u.GetAll()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	result := make([]*database.User, 0, len(users))
	for _, v := range users {
		if v.Type == database.UserTypeServiceAccount {
			result = append(result, v)
		}
	}

	return result, nil
}

func (u *UserDatabase) GetAccessToken(value string) (*database.AccessToken, error) {
	at, err := u.dao.AccessToken.SelectAccessToken(context.TODO(), value)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return &database.AccessToken{
		Name:      at.Name,
		Value:     at.Value,
		UserId:    at.User.Identity,
		Issuer:    at.Issuer.Identity,
		CreatedAt: at.CreatedAt,
	}, nil
}

func (u *UserDatabase) GetAccessTokens(id string) ([]*database.AccessToken, error) {
	user, err := u.dao.User.SelectIdentity(context.TODO(), id)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	tokens, err := u.dao.AccessToken.ListByUser(context.TODO(), user.Id)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	result := make([]*database.AccessToken, len(tokens))
	for i, v := range tokens {
		result[i] = &database.AccessToken{
			Name:      v.Name,
			Value:     v.Value,
			UserId:    v.User.Identity,
			Issuer:    v.Issuer.Identity,
			CreatedAt: v.CreatedAt,
		}
	}

	return result, nil
}

func (u *UserDatabase) Set(ctx context.Context, user *database.User) error {
	existUser, _ := u.dao.User.SelectIdentity(ctx, user.Id)
	if existUser == nil {
		created, err := u.dao.User.Create(ctx, &entity.User{
			Identity: user.Id,
			Admin:    user.Admin,
			Type:     user.Type,
			Comment:  user.Comment,
		})
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}
		existUser = created
	} else {
		existUser.Admin = user.Admin
		existUser.Type = user.Type
		existUser.Comment = user.Comment
		if err := u.dao.User.Update(ctx, existUser); err != nil {
			return xerrors.Errorf(": %w", err)
		}
	}

	roles, err := u.dao.RoleBinding.ListUser(ctx, existUser.Id)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	currentRole := make(map[string]*entity.RoleBinding)
	for _, v := range roles {
		currentRole[v.Role] = v
	}
	modifiedRole := make(map[string]*entity.RoleBinding)
	for _, v := range user.Roles {
		modifiedRole[v] = &entity.RoleBinding{Role: v, UserId: existUser.Id}
		if m, ok := user.MaintainRoles[v]; ok && m {
			modifiedRole[v].Maintainer = true
		}
	}

	// Delete
	for r, v := range currentRole {
		if _, ok := modifiedRole[r]; !ok {
			if err := u.dao.RoleBinding.Delete(ctx, v.Id); err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}
	// Create
	for r, v := range modifiedRole {
		if _, ok := currentRole[r]; !ok {
			if _, err := u.dao.RoleBinding.Create(ctx, v); err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}
	// Edit
	for r, v := range modifiedRole {
		if c, ok := currentRole[r]; ok && c.Maintainer != v.Maintainer {
			c.Maintainer = v.Maintainer
			if err := u.dao.RoleBinding.Update(ctx, c); err != nil {
				return xerrors.Errorf(": %w", err)
			}
		}
	}

	return nil
}

func (u *UserDatabase) SetAccessToken(ctx context.Context, token *database.AccessToken) error {
	user, err := u.dao.User.SelectIdentity(ctx, token.UserId)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	issuer, err := u.dao.User.SelectIdentity(ctx, token.Issuer)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	_, err = u.dao.AccessToken.Create(ctx, &entity.AccessToken{
		Name:     token.Name,
		Value:    token.Value,
		UserId:   user.Id,
		IssuerId: issuer.Id,
	})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (u *UserDatabase) Delete(ctx context.Context, id string) error {
	user, err := u.dao.User.SelectIdentity(ctx, id)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	err = u.dao.User.Delete(ctx, user.Id)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (u *UserDatabase) SetState(ctx context.Context, unique string) (string, error) {
	buf := make([]byte, 10)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", xerrors.Errorf("database: failure generate state: %v", err)
	}
	stateString := base64.StdEncoding.EncodeToString(buf)

	_, err := u.dao.UserState.Create(ctx, &entity.UserState{
		State:  stateString[:len(stateString)-2],
		Unique: unique,
	})
	if err != nil {
		return "", xerrors.Errorf(": %w", err)
	}

	return stateString[:len(stateString)-2], nil
}

func (u *UserDatabase) GetState(ctx context.Context, state string) (string, error) {
	s, err := u.dao.UserState.SelectState(ctx, state)
	if err != nil {
		return "", xerrors.Errorf(": %w", err)
	}

	return s.Unique, nil
}

func (u *UserDatabase) DeleteState(ctx context.Context, state string) error {
	s, err := u.dao.UserState.SelectState(ctx, state)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	err = u.dao.UserState.Delete(ctx, s.Id)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (u *UserDatabase) GetSSHKeys(ctx context.Context, id string) (*database.SSHKeys, error) {
	user, err := u.dao.User.SelectIdentity(ctx, id)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	key, err := u.dao.SSHKey.Select(ctx, user.Id)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return &database.SSHKeys{UserId: user.Identity, Keys: key.Key}, nil
}

func (u *UserDatabase) SetSSHKeys(ctx context.Context, keys *database.SSHKeys) error {
	user, err := u.dao.User.SelectIdentity(ctx, keys.UserId)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	k, err := u.dao.SSHKey.Select(ctx, user.Id)
	if err == sql.ErrNoRows {
		k = &entity.SSHKey{UserId: user.Id, Key: keys.Keys}

		_, err = u.dao.SSHKey.Create(ctx, k)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		return nil
	}
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	k.Key = keys.Keys
	err = u.dao.SSHKey.Update(ctx, k)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (u *UserDatabase) GetGPGKey(ctx context.Context, id string) (*database.GPGKey, error) {
	user, err := u.dao.User.SelectIdentity(ctx, id)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	key, err := u.dao.GPGKey.Select(ctx, user.Id)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return &database.GPGKey{UserId: user.Identity, Key: key.Key}, nil
}

func (u *UserDatabase) SetGPGKey(ctx context.Context, key *database.GPGKey) error {
	user, err := u.dao.User.SelectIdentity(ctx, key.UserId)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	k, err := u.dao.GPGKey.Select(ctx, user.Id)
	if err == sql.ErrNoRows {
		k = &entity.GPGKey{UserId: user.Id, Key: key.Key}

		_, err = u.dao.GPGKey.Create(ctx, k)
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		return nil
	}
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	k.Key = key.Key
	err = u.dao.GPGKey.Update(ctx, k)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}
