package database

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/f110/lagrangian-proxy/pkg/logger"
	"go.uber.org/zap"
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

type TokenCrawler struct {
	database TokenDatabase
}

func NewTokenCrawler(d TokenDatabase) *TokenCrawler {
	return &TokenCrawler{database: d}
}

func (c *TokenCrawler) Crawl(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	logger.Log.Info("Start TokenCrawler")
	if err := c.crawl(ctx); err != nil {
		logger.Log.Error("Failed crawl token database", zap.Error(err))
	}

	for {
		select {
		case <-ticker.C:
			if err := c.crawl(ctx); err != nil {
				logger.Log.Error("Failed crawl token database", zap.Error(err))
			}
		case <-ctx.Done():
			return
		}
	}
}

func (c *TokenCrawler) crawl(ctx context.Context) error {
	codes, err := c.database.AllCodes(ctx)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	for _, code := range codes {
		if code.IssuedAt.Add(CodeExpiration).Before(time.Now()) {
			logger.Log.Debug("Remove code", zap.String("code", code.Code), zap.Time("issued_at", code.IssuedAt))
			if err := c.database.DeleteCode(ctx, code.Code); err != nil {
				return xerrors.Errorf(": %v", err)
			}
		}
	}

	tokens, err := c.database.AllTokens(ctx)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	for _, token := range tokens {
		if token.IssuedAt.Add(TokenExpiration).Before(time.Now()) {
			logger.Log.Debug("Remove token", zap.String("token", token.Token), zap.Time("issued_at", token.IssuedAt))
			if err := c.database.DeleteToken(ctx, token.Token); err != nil {
				return xerrors.Errorf(": %v", err)
			}
		}
	}

	return nil
}
