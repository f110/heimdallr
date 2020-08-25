package mysql

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"time"

	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/database/mysql/dao"
	"go.f110.dev/heimdallr/pkg/database/mysql/entity"
)

type TokenDatabase struct {
	dao *dao.Repository
}

var _ database.TokenDatabase = &TokenDatabase{}

func NewTokenDatabase(dao *dao.Repository) *TokenDatabase {
	return &TokenDatabase{dao: dao}
}

func (t *TokenDatabase) FindToken(ctx context.Context, token string) (*database.Token, error) {
	tokens, err := t.dao.Token.ListToken(ctx, token)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if len(tokens) != 1 {
		return nil, sql.ErrNoRows
	}

	return &database.Token{
		Token:    tokens[0].Token,
		UserId:   tokens[0].User.Identity,
		IssuedAt: tokens[0].IssuedAt,
	}, nil
}

func (t *TokenDatabase) NewCode(ctx context.Context, userId, challenge, challengeMethod string) (*database.Code, error) {
	code, err := newCode()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	user, err := t.dao.User.SelectIdentity(ctx, userId)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	newCode, err := t.dao.Code.Create(ctx, &entity.Code{
		Code:            code,
		Challenge:       challenge,
		ChallengeMethod: challengeMethod,
		UserId:          user.Id,
		IssuedAt:        time.Now(),
	})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	return &database.Code{
		Code:            newCode.Code,
		Challenge:       newCode.Challenge,
		ChallengeMethod: newCode.ChallengeMethod,
		UserId:          user.Identity,
		IssuedAt:        newCode.IssuedAt,
	}, nil
}

func (t *TokenDatabase) IssueToken(ctx context.Context, code, codeVerifier string) (*database.Token, error) {
	c, err := t.dao.Code.SelectCode(ctx, code)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	v := &database.Code{
		Code:            c.Code,
		Challenge:       c.Challenge,
		ChallengeMethod: c.ChallengeMethod,
		UserId:          c.User.Identity,
		IssuedAt:        c.IssuedAt,
	}
	if !v.Verify(codeVerifier) {
		return nil, xerrors.New("mysql: code verify error")
	}

	if err := t.dao.Code.Delete(ctx, c.Id); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	token, err := newCode()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	newToken, err := t.dao.Token.Create(ctx, &entity.Token{
		Token:    token,
		UserId:   c.User.Id,
		IssuedAt: time.Now(),
	})
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return &database.Token{
		Token:    token,
		UserId:   c.User.Identity,
		IssuedAt: newToken.IssuedAt,
	}, nil
}

func (t *TokenDatabase) AllCodes(ctx context.Context) ([]*database.Code, error) {
	codes, err := t.dao.Code.ListAll(ctx)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	result := make([]*database.Code, len(codes))
	for i, v := range codes {
		result[i] = &database.Code{
			Code:            v.Code,
			Challenge:       v.Challenge,
			ChallengeMethod: v.ChallengeMethod,
			UserId:          v.User.Identity,
			IssuedAt:        v.IssuedAt,
		}
	}

	return result, nil
}

func (t *TokenDatabase) DeleteCode(ctx context.Context, code string) error {
	c, err := t.dao.Code.SelectCode(ctx, code)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	err = t.dao.Code.Delete(ctx, c.Id)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (t *TokenDatabase) AllTokens(ctx context.Context) ([]*database.Token, error) {
	tokens, err := t.dao.Token.ListAll(ctx)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	result := make([]*database.Token, len(tokens))
	for i, v := range tokens {
		result[i] = &database.Token{
			Token:    v.Token,
			UserId:   v.User.Identity,
			IssuedAt: v.IssuedAt,
		}
	}

	return result, nil
}

func (t *TokenDatabase) DeleteToken(ctx context.Context, token string) error {
	tokens, err := t.dao.Token.ListToken(ctx, token)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if len(tokens) != 1 {
		return sql.ErrNoRows
	}

	err = t.dao.Token.Delete(ctx, tokens[0].Id)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func newCode() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
