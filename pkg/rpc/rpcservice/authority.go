package rpcservice

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/dgrijalva/jwt-go"
	"go.uber.org/zap"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc"
)

var TokenExpiration = 5 * time.Minute

type AuthorityService struct {
	Config *config.Config
}

var _ rpc.AuthorityServer = &AuthorityService{}

func NewAuthorityService(conf *config.Config) *AuthorityService {
	return &AuthorityService{Config: conf}
}

func (a *AuthorityService) SignRequest(_ context.Context, req *rpc.RequestSignRequest) (*rpc.ResponseSignResponse, error) {
	claim := jwt.NewWithClaims(jwt.SigningMethodES256, &jwt.StandardClaims{
		Id:        req.UserId,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(TokenExpiration).Unix(),
	})
	token, err := claim.SignedString(a.Config.General.SigningPrivateKey)
	if err != nil {
		logger.Log.Info("Failed sign jwt", zap.Error(err))
		return nil, err
	}

	return &rpc.ResponseSignResponse{Token: token}, nil
}

func (a *AuthorityService) GetPublicKey(_ context.Context, req *rpc.RequestGetPublicKey) (*rpc.ResponseGetPublicKey, error) {
	b, err := x509.MarshalPKIXPublicKey(a.Config.General.SigningPublicKey)
	if err != nil {
		logger.Log.Error("Failed marshal public key", zap.Error(err))
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "PUBLIC KEY", Bytes: b}); err != nil {
		logger.Log.Error("Failed pem encode", zap.Error(err))
	}

	return &rpc.ResponseGetPublicKey{PublicKey: buf.Bytes()}, nil
}
