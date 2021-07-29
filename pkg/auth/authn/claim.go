package authn

import (
	"github.com/golang-jwt/jwt"
)

type TokenClaims struct {
	jwt.StandardClaims
	Roles []string `json:"roles,omitempty"`
}
