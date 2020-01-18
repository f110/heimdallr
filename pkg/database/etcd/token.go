package etcd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/coreos/etcd/clientv3"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
	"sigs.k8s.io/yaml"

	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
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

	lease, err := t.client.Grant(ctx, int64(database.CodeExpiration.Seconds()))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	_, err = t.client.Put(ctx, fmt.Sprintf("code/%s", code), string(b), clientv3.WithLease(lease.ID))
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
	lease, err := t.client.Grant(ctx, int64(database.TokenExpiration.Seconds()))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	_, err = t.client.Put(ctx, fmt.Sprintf("token/%s", s), string(b), clientv3.WithLease(lease.ID))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	return token, nil
}

func (t *TemporaryToken) AllCodes(ctx context.Context) ([]*database.Code, error) {
	res, err := t.client.Get(ctx, "code/", clientv3.WithPrefix())
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	codes := make([]*database.Code, 0, res.Count)
	for _, v := range res.Kvs {
		c := &database.Code{}
		if err := yaml.Unmarshal(v.Value, c); err != nil {
			return nil, xerrors.Errorf(": $v", err)
		}
		codes = append(codes, c)
	}

	return codes, nil
}

func (t *TemporaryToken) DeleteCode(ctx context.Context, code string) error {
	_, err := t.client.Delete(ctx, fmt.Sprintf("code/%s", code))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	return nil
}

func (t *TemporaryToken) AllTokens(ctx context.Context) ([]*database.Token, error) {
	res, err := t.client.Get(ctx, "token/", clientv3.WithPrefix())
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	tokens := make([]*database.Token, 0, res.Count)
	for _, v := range res.Kvs {
		tk := &database.Token{}
		if err := yaml.Unmarshal(v.Value, tk); err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}
		tokens = append(tokens, tk)
	}

	return tokens, nil
}

func (t *TemporaryToken) DeleteToken(ctx context.Context, token string) error {
	_, err := t.client.Delete(ctx, fmt.Sprintf("token/%s", token))
	if err != nil {
		return xerrors.Errorf(": %v", err)
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
