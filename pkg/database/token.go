package database

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"golang.org/x/xerrors"
)

var (
	ErrTokenNotFound = xerrors.New("database: token not found")
)

var (
	CodeExpiration  = 1 * time.Minute
	TokenExpiration = 24 * time.Hour
)

type TokenDatabase interface {
	FindToken(ctx context.Context, token string) (*Token, error)
	NewCode(ctx context.Context, userId, challenge, challengeMethod string) (*Code, error)
	IssueToken(ctx context.Context, code, codeVerifier string) (*Token, error)
	AllCodes(ctx context.Context) ([]*Code, error)
	DeleteCode(ctx context.Context, code string) error
	AllTokens(ctx context.Context) ([]*Token, error)
	DeleteToken(ctx context.Context, token string) error
}

type Token struct {
	Token    string    `json:"token"`
	UserId   string    `json:"user_id"`
	IssuedAt time.Time `json:"issued_at"`
}

type Code struct {
	Code            string    `json:"code"`
	Challenge       string    `json:"challenge"`
	ChallengeMethod string    `json:"challenge_method"`
	UserId          string    `json:"user_id"`
	IssuedAt        time.Time `json:"issued_at"`
}

func (c *Code) Verify(verifier string) bool {
	switch c.ChallengeMethod {
	case "plain":
		return c.Challenge == verifier
	case "S256":
		s := sha256.New()
		s.Write([]byte(verifier))
		result := s.Sum(nil)
		return base64.StdEncoding.EncodeToString(result) == c.Challenge
	default:
		return false
	}
}
