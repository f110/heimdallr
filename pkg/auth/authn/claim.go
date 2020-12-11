package authn

import (
	"github.com/dgrijalva/jwt-go"
)

type TokenClaims struct {
	jwt.StandardClaims
	Roles []string `json:"roles,omitempty"`
}
