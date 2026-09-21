package dashboard

import (
	"context"
	"crypto"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v4"
	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/auth/authn"
	"go.f110.dev/heimdallr/pkg/authproxy"
	"go.f110.dev/heimdallr/pkg/logger"
)

type verifiedUserIdKey struct{}

type userTokenKey struct{}

var (
	VerifiedUserIdKey = verifiedUserIdKey{}
	UserTokenKey      = userTokenKey{}
)

// verifyToken parses the token that authproxy put into the request header and verifies the
// signature with the public key of the proxy.
func verifyToken(token string, publicKey crypto.PublicKey) (*authn.TokenClaims, error) {
	claim := &authn.TokenClaims{}
	if _, err := jwt.ParseWithClaims(token, claim, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodES256 {
			return nil, xerrors.New("dashboard: invalid signing method")
		}
		return publicKey, nil
	}); err != nil {
		logger.Log.Info("Failed parse JWT", slog.Any("error", err))
		return nil, err
	}
	if err := claim.Valid(); err != nil {
		logger.Log.Warn("Invalid JWT token", slog.Any("error", err))
		return nil, err
	}

	return claim, nil
}

func newAuthInterceptor(publicKey crypto.PublicKey) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			token := req.Header().Get(authproxy.TokenHeaderName)
			if token == "" {
				return nil, connect.NewError(connect.CodeUnauthenticated, xerrors.New("dashboard: token is empty"))
			}

			claim, err := verifyToken(token, publicKey)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, err)
			}

			ctx = context.WithValue(ctx, VerifiedUserIdKey, claim.Subject)
			ctx = context.WithValue(ctx, UserTokenKey, token)
			return next(ctx, req)
		}
	}
}

func newAccessLogInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			start := time.Now()
			res, err := next(ctx, req)
			// connect.Code carries the same numbers as the status codes of gRPC. Zero is not one
			// of them and stands for a call that succeeded.
			code := 0
			if err != nil {
				code = int(connect.CodeOf(err))
			}
			logger.Log.Info("Access",
				slog.String("procedure", req.Spec().Procedure),
				slog.Int("code", code),
				slog.Duration("duration", time.Since(start)),
			)
			return res, err
		}
	}
}
