package rpcservice

import (
	"context"
	"math/big"

	"github.com/f110/lagrangian-proxy/pkg/config"

	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc"
	"go.uber.org/zap"
	"golang.org/x/xerrors"
)

type CertificateAuthorityService struct {
	Config *config.Config
	ca     database.CertificateAuthority
}

var _ rpc.CertificateAuthorityServer = &CertificateAuthorityService{}

func NewCertificateAuthorityService(conf *config.Config, ca database.CertificateAuthority) *CertificateAuthorityService {
	return &CertificateAuthorityService{Config: conf, ca: ca}
}

func (s *CertificateAuthorityService) CertList(ctx context.Context, _ *rpc.RequestCertList) (*rpc.ResponseCertList, error) {
	certs, err := s.ca.GetSignedCertificates(ctx)
	if err != nil {
		return nil, err
	}

	res := make([]*rpc.CertItem, len(certs))
	for i, c := range certs {
		res[i] = rpc.DatabaseCertToRPCCert(c)
	}

	return &rpc.ResponseCertList{Items: res}, nil
}

func (s *CertificateAuthorityService) RevokedCertList(_ context.Context, _ *rpc.RequestRevokedCertList) (*rpc.ResponseRevokedCertList, error) {
	certs := s.ca.GetRevokedCertificates()

	res := make([]*rpc.CertItem, len(certs))
	for i, c := range certs {
		res[i] = rpc.DatabaseRevokedCertToRPCCert(c)
	}

	return &rpc.ResponseRevokedCertList{Items: res}, nil
}

func (s *CertificateAuthorityService) CertNew(ctx context.Context, req *rpc.RequestCertNew) (*rpc.ResponseCertNew, error) {
	var err error
	if req.Agent {
		if _, ok := s.Config.General.GetBackend(req.CommonName); !ok {
			return nil, xerrors.New("rpc: unknown backend")
		}

		_, err = s.ca.NewAgentCertificate(ctx, req.CommonName, req.Comment)
	} else {
		_, err = s.ca.NewClientCertificate(ctx, req.CommonName, req.Password, req.Comment)
	}
	if err != nil {
		return nil, err
	}

	logger.Audit.Info("Generate certificate", zap.String("common_name", req.CommonName), auditBy(ctx))
	return &rpc.ResponseCertNew{Ok: true}, nil
}

func (s *CertificateAuthorityService) CertRevoke(ctx context.Context, req *rpc.RequestCertRevoke) (*rpc.ResponseCertRevoke, error) {
	serialNumber := big.NewInt(0)
	serialNumber.SetBytes(req.SerialNumber)

	signed, err := s.ca.GetSignedCertificate(ctx, serialNumber)
	if err != nil {
		return nil, err
	}

	err = s.ca.Revoke(ctx, signed)
	if err != nil {
		return nil, err
	}

	logger.Audit.Info("Revoke certificate", zap.String("common_name", signed.Certificate.Subject.CommonName), auditBy(ctx))
	return &rpc.ResponseCertRevoke{Ok: true}, nil
}

func (s *CertificateAuthorityService) CertGet(ctx context.Context, req *rpc.RequestCertGet) (*rpc.ResponseCertGet, error) {
	serialNumber := big.NewInt(0)
	serialNumber.SetBytes(req.SerialNumber)

	cert, err := s.ca.GetSignedCertificate(ctx, serialNumber)
	if err != nil {
		return nil, err
	}

	return &rpc.ResponseCertGet{Item: rpc.DatabaseCertToRPCCertWithByte(cert)}, nil
}
