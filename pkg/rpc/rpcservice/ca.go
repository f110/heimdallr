package rpcservice

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/f110/lagrangian-proxy/pkg/cert"
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

func (s *CertificateAuthorityService) GetSignedList(ctx context.Context, _ *rpc.RequestGetSignedList) (*rpc.ResponseGetSignedList, error) {
	certs, err := s.ca.GetSignedCertificates(ctx)
	if err != nil {
		return nil, err
	}

	res := make([]*rpc.CertItem, len(certs))
	for i, c := range certs {
		res[i] = rpc.DatabaseCertToRPCCert(c)
	}

	return &rpc.ResponseGetSignedList{Items: res}, nil
}

func (s *CertificateAuthorityService) NewClientCert(ctx context.Context, req *rpc.RequestNewClientCert) (*rpc.ResponseNewClientCert, error) {
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
	return &rpc.ResponseNewClientCert{Ok: true}, nil
}

func (s *CertificateAuthorityService) Revoke(ctx context.Context, req *rpc.CARequestRevoke) (*rpc.CAResponseRevoke, error) {
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
	return &rpc.CAResponseRevoke{Ok: true}, nil
}

func (s *CertificateAuthorityService) Get(ctx context.Context, req *rpc.CARequestGet) (*rpc.CAResponseGet, error) {
	serialNumber := big.NewInt(0)
	serialNumber.SetBytes(req.SerialNumber)

	c, err := s.ca.GetSignedCertificate(ctx, serialNumber)
	if err != nil {
		return nil, err
	}

	return &rpc.CAResponseGet{Item: rpc.DatabaseCertToRPCCertWithByte(c)}, nil
}

func (s *CertificateAuthorityService) NewServerCert(ctx context.Context, req *rpc.RequestNewServerCert) (*rpc.ResponseNewServerCert, error) {
	b, _ := pem.Decode(req.SigningRequest)
	if b.Type != "CERTIFICATE REQUEST" {
		return nil, xerrors.New("rpcservice: invalid certificate signing request")
	}
	signingRequest, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, err
	}

	c, err := cert.SigningCertificateRequest(signingRequest, s.Config.General.CertificateAuthority)
	if err != nil {
		return nil, err
	}

	logger.Audit.Info("Signing Certificate", zap.String("common_name", signingRequest.Subject.CommonName), zap.Int64("serial_number", c.SerialNumber.Int64()), auditBy(ctx))
	return &rpc.ResponseNewServerCert{Certificate: c.Raw}, nil
}

func (s *CertificateAuthorityService) GetRevokedList(_ context.Context, _ *rpc.RequestGetRevokedList) (*rpc.ResponseGetRevokedList, error) {
	revoked := s.ca.GetRevokedCertificates()
	res := make([]*rpc.CertItem, len(revoked))
	for i, v := range revoked {
		res[i] = rpc.DatabaseRevokedCertToRPCCert(v)
	}

	return &rpc.ResponseGetRevokedList{Items: res}, nil
}

func (s *CertificateAuthorityService) WatchRevokedCert(_ *rpc.RequestWatchRevokedCert, ss rpc.CertificateAuthority_WatchRevokedCertServer) error {
	ch := s.ca.WatchRevokeCertificate()
	defer func() {
		close(ch)
	}()

	revoked := s.ca.GetRevokedCertificates()
	res := make([]*rpc.CertItem, len(revoked))
	for i, v := range revoked {
		res[i] = rpc.DatabaseRevokedCertToRPCCert(v)
	}
	if err := ss.Send(&rpc.ResponseWatchRevokedCert{Items: res}); err != nil {
		return err
	}

	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case v := <-ch:
			if err := ss.Send(&rpc.ResponseWatchRevokedCert{Items: []*rpc.CertItem{rpc.DatabaseRevokedCertToRPCCert(v)}}); err != nil {
				return err
			}
		case <-t.C:
			if err := ss.Send(&rpc.ResponseWatchRevokedCert{Items: []*rpc.CertItem{}}); err != nil {
				return err
			}
		case <-ss.Context().Done():
			return nil
		}
	}
}
