package rpcservice

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"time"

	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/connector"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/rpc"
)

type CertificateAuthorityService struct {
	Config *configv2.Config
	ca     *cert.CertificateAuthority
}

var _ rpc.CertificateAuthorityServer = &CertificateAuthorityService{}

func NewCertificateAuthorityService(conf *configv2.Config, ca *cert.CertificateAuthority) *CertificateAuthorityService {
	return &CertificateAuthorityService{Config: conf, ca: ca}
}

func (s *CertificateAuthorityService) GetSignedList(ctx context.Context, req *rpc.RequestGetSignedList) (*rpc.ResponseGetSignedList, error) {
	certs, err := s.ca.GetSignedCertificates(ctx)
	if err != nil {
		return nil, err
	}

	res := make([]*rpc.CertItem, 0, len(certs))
	for _, c := range certs {
		if req.CommonName != "" && req.CommonName != c.Certificate.Subject.CommonName {
			continue
		}
		if req.Device && !c.Device {
			continue
		}

		res = append(res, rpc.DatabaseCertToRPCCert(c))
	}

	return &rpc.ResponseGetSignedList{Items: res}, nil
}

func (s *CertificateAuthorityService) NewClientCert(ctx context.Context, req *rpc.RequestNewClientCert) (*rpc.ResponseNewClientCert, error) {
	var err error
	commonName := req.GetCommonName()

	var csr *x509.CertificateRequest
	if req.GetCsr() != "" {
		block, _ := pem.Decode([]byte(req.GetCsr()))
		if block.Type != "CERTIFICATE REQUEST" {
			return nil, errors.New("rpcservice: invalid csr")
		}
		r, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, err
		}
		commonName = r.Subject.CommonName
		csr = r
	}
	if req.OverrideCommonName != "" {
		commonName = req.GetOverrideCommonName()
		if csr != nil {
			csr.Subject.CommonName = req.GetOverrideCommonName()
		}
	}

	if req.GetAgent() {
		if _, ok := s.Config.AccessProxy.GetBackend(commonName); !ok {
			logger.Log.Info("Could not find backend", zap.String("common_name", req.GetCommonName()))
			return nil, xerrors.New("rpcservice: unknown backend")
		}
	}

	if commonName == "" {
		return nil, errors.New("rpcservice: the common name is mandatory")
	}
	if req.GetCsr() != "" && req.GetOverrideCommonName() == "" && req.GetCommonName() != commonName {
		return nil, errors.New("rpcservice: Subject.CommonName and req.CommonName are not same value")
	}

	var signed *database.SignedCertificate
	if csr == nil {
		if req.GetAgent() {
			signed, err = s.ca.NewAgentCertificate(ctx, req.GetCommonName(), connector.DefaultCertificatePassword, req.GetComment())
		} else {
			signed, err = s.ca.NewClientCertificate(ctx, req.GetCommonName(), req.GetKeyType(), int(req.GetKeyBits()), req.GetPassword(), req.GetComment())
		}
	} else {
		signed, err = s.ca.SignCertificateRequest(ctx, csr, req.GetComment(), req.GetAgent(), req.GetDevice())
	}
	if err != nil {
		return nil, err
	}

	logger.Audit.Info("Generate certificate", zap.String("common_name", commonName), auditBy(ctx))
	return &rpc.ResponseNewClientCert{Ok: true, Certificate: rpc.DatabaseCertToRPCCertWithByte(signed)}, nil
}

func (s *CertificateAuthorityService) Revoke(ctx context.Context, req *rpc.CARequestRevoke) (*rpc.CAResponseRevoke, error) {
	serialNumber := big.NewInt(0)
	serialNumber.SetBytes(req.GetSerialNumber())

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
	serialNumber.SetBytes(req.GetSerialNumber())

	c, err := s.ca.GetSignedCertificate(ctx, serialNumber)
	if err != nil {
		return nil, err
	}

	return &rpc.CAResponseGet{Item: rpc.DatabaseCertToRPCCertWithByte(c)}, nil
}

func (s *CertificateAuthorityService) NewServerCert(ctx context.Context, req *rpc.RequestNewServerCert) (*rpc.ResponseNewServerCert, error) {
	b, _ := pem.Decode(req.GetSigningRequest())
	if b.Type != "CERTIFICATE REQUEST" {
		return nil, xerrors.New("rpcservice: invalid certificate signing request")
	}
	signingRequest, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, err
	}

	c, err := cert.SigningCertificateRequest(signingRequest, s.Config.CertificateAuthority.Local)
	if err != nil {
		return nil, err
	}

	logger.Audit.Info("Signing Certificate", zap.String("common_name", signingRequest.Subject.CommonName), zap.Int64("serial_number", c.SerialNumber.Int64()), auditBy(ctx))
	return &rpc.ResponseNewServerCert{Certificate: c.Raw}, nil
}

func (s *CertificateAuthorityService) GetRevokedList(ctx context.Context, _ *rpc.RequestGetRevokedList) (*rpc.ResponseGetRevokedList, error) {
	revoked, err := s.ca.GetRevokedCertificates(ctx)
	if err != nil {
		return nil, err
	}
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

	revoked, err := s.ca.GetRevokedCertificates(context.Background())
	if err != nil {
		return err
	}

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
