package authn

import (
	"github.com/golang-jwt/jwt/v4"
)

type TokenClaims struct {
	jwt.RegisteredClaims
	Roles []string `json:"roles,omitempty"`
}
