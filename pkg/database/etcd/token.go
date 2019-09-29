package etcd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"
)

type TemporaryToken struct {
	client *clientv3.Client
}

var _ database.TokenDatabase = &TemporaryToken{}

func NewTemporaryToken(client *clientv3.Client) *TemporaryToken {
	return &TemporaryToken{client: client}
}

func (t *TemporaryToken) FindToken(ctx context.Context, token string) (*database.Token, error) {
	res, err := t.client.Get(ctx, fmt.Sprintf("token/%s", token))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	if res.Count == 0 {
		return nil, database.ErrTokenNotFound
	}

	tk := &database.Token{}
	if err := yaml.Unmarshal(res.Kvs[0].Value, tk); err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	if tk.IssuedAt.Add(database.TokenExpiration).Before(time.Now()) {
		return nil, database.ErrTokenNotFound
	}
	return tk, nil
}

func (t *TemporaryToken) NewCode(ctx context.Context, userId, challenge, challengeMethod string) (*database.Code, error) {
	code, err := newCode()
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	c := &database.Code{
		Code:            code,
		UserId:          userId,
		Challenge:       challenge,
		ChallengeMethod: challengeMethod,
		IssuedAt:        time.Now(),
	}

	b, err := yaml.Marshal(c)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	_, err = t.client.Put(ctx, fmt.Sprintf("code/%s", code), string(b))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	return c, nil
}

func (t *TemporaryToken) IssueToken(ctx context.Context, code, codeVerifier string) (*database.Token, error) {
	res, err := t.client.Get(ctx, fmt.Sprintf("code/%s", code))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	if res.Count == 0 {
		return nil, xerrors.New("etcd: code not found")
	}
	c := &database.Code{}
	if err := yaml.Unmarshal(res.Kvs[0].Value, c); err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	if c.IssuedAt.Add(database.CodeExpiration).Before(time.Now()) {
		return nil, xerrors.New("etcd: code is expired")
	}
	if !c.Verify(codeVerifier) {
		logger.Log.Debug("code verifier", zap.String("code_verifier", codeVerifier))
		return nil, xerrors.New("etcd: code verify failure")
	}

	_, err = t.client.Delete(ctx, fmt.Sprintf("code/%s", code))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	s, err := newCode()
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	token := &database.Token{Token: s, UserId: c.UserId, IssuedAt: time.Now()}
	b, err := yaml.Marshal(token)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	_, err = t.client.Put(ctx, fmt.Sprintf("token/%s", s), string(b))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	return token, nil
}

func newCode() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
