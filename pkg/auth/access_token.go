package auth

import (
	"math/rand"
	"time"

	"go.f110.dev/heimdallr/pkg/database"
)

const (
	AccessTokenLength = 32
	letters           = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

func NewAccessToken(name, userId, issuer string) (*database.AccessToken, error) {
	b := make([]byte, AccessTokenLength)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}

	return &database.AccessToken{
		Name:      name,
		Value:     string(b),
		UserId:    userId,
		Issuer:    issuer,
		CreatedAt: time.Now(),
	}, nil
}
