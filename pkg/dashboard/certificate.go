package dashboard

import (
	"context"
	"sort"

	"connectrpc.com/connect"
	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/rpc"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
)

type CertificateService struct {
	service
}

var _ CertificateServiceHandler = &CertificateService{}

func NewCertificateService(c *rpcclient.ClientWithUserToken) *CertificateService {
	return &CertificateService{rpcClient: c}
}

func (s *CertificateService) ListCertificates(ctx context.Context, _ *connect.Request[ListCertificatesRequest]) (*connect.Response[ListCertificatesResponse], error) {
	signed, revoked, err := s.listCertificates(ctx, false)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&ListCertificatesResponse{Signed: signed, Revoked: revoked}), nil
}

func (s *CertificateService) NewClientCertificate(ctx context.Context, req *connect.Request[NewClientCertificateRequest]) (*connect.Response[NewClientCertificateResponse], error) {
	client := s.client(ctx)

	if req.Msg.Csr != "" {
		if _, err := client.NewCertByCSR(ctx, req.Msg.Csr, rpcclient.VerifyCommonName(req.Msg.Id)); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}

		return connect.NewResponse(&NewClientCertificateResponse{}), nil
	}

	keyType, err := keyTypeName(req.Msg.KeyType)
	if err != nil {
		return nil, err
	}
	err = client.NewCert(ctx, req.Msg.Id, keyType, int(req.Msg.KeyBits), req.Msg.Password, req.Msg.Comment)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&NewClientCertificateResponse{}), nil
}

func (s *CertificateService) RevokeCertificate(ctx context.Context, req *connect.Request[RevokeCertificateRequest]) (*connect.Response[RevokeCertificateResponse], error) {
	serialNumber, err := parseSerialNumber(req.Msg.SerialNumber)
	if err != nil {
		return nil, err
	}

	if err := s.client(ctx).RevokeCert(ctx, serialNumber); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&RevokeCertificateResponse{}), nil
}

func (s *CertificateService) ListAgents(ctx context.Context, _ *connect.Request[ListAgentsRequest]) (*connect.Response[ListAgentsResponse], error) {
	signed, revoked, err := s.listCertificates(ctx, true)
	if err != nil {
		return nil, err
	}

	agents, err := s.client(ctx).ListConnectedAgent(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	connected := make([]*Agent, 0, len(agents))
	for _, v := range agents {
		connected = append(connected, newAgent(v))
	}

	return connect.NewResponse(&ListAgentsResponse{Connected: connected, Signed: signed, Revoked: revoked}), nil
}

func (s *CertificateService) ListAgentBackends(ctx context.Context, _ *connect.Request[ListAgentBackendsRequest]) (*connect.Response[ListAgentBackendsResponse], error) {
	backends, err := s.client(ctx).ListAgentBackend(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	names := make([]string, 0, len(backends))
	for _, v := range backends {
		for _, h := range v.HttpBackends {
			names = append(names, v.Name+h.Path)
		}
		if v.SocketBackend != nil {
			names = append(names, v.Name)
		}
	}

	return connect.NewResponse(&ListAgentBackendsResponse{Names: names}), nil
}

func (s *CertificateService) RegisterAgent(ctx context.Context, req *connect.Request[RegisterAgentRequest]) (*connect.Response[RegisterAgentResponse], error) {
	if req.Msg.Id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, xerrors.New("dashboard: id is empty"))
	}
	client := s.client(ctx)

	if req.Msg.Csr != "" {
		if _, err := client.NewAgentCertByCSR(ctx, req.Msg.Csr, req.Msg.Id); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}

		return connect.NewResponse(&RegisterAgentResponse{}), nil
	}

	if err := client.NewAgentCert(ctx, req.Msg.Id, req.Msg.Comment); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&RegisterAgentResponse{}), nil
}

// listCertificates returns the signed and the revoked certificates of either the agents or the
// clients. Both are held by the same rpc and told apart by the Agent flag.
func (s *CertificateService) listCertificates(ctx context.Context, agent bool) ([]*Certificate, []*Certificate, error) {
	client := s.client(ctx)

	signed, err := client.ListCert(ctx)
	if err != nil {
		return nil, nil, connect.NewError(connect.CodeInternal, err)
	}
	signedCertificates := filterCertificates(signed, agent)
	sort.Slice(signedCertificates, func(i, j int) bool {
		return timestampSeconds(signedCertificates[i].IssuedAt) > timestampSeconds(signedCertificates[j].IssuedAt)
	})

	revoked, err := client.ListRevokedCert(ctx)
	if err != nil {
		return nil, nil, connect.NewError(connect.CodeInternal, err)
	}
	revokedCertificates := filterCertificates(revoked, agent)
	sort.Slice(revokedCertificates, func(i, j int) bool {
		return timestampSeconds(revokedCertificates[i].RevokedAt) > timestampSeconds(revokedCertificates[j].RevokedAt)
	})

	return signedCertificates, revokedCertificates, nil
}

func filterCertificates(in []*rpc.CertItem, agent bool) []*Certificate {
	res := make([]*Certificate, 0, len(in))
	for _, v := range in {
		if v.Agent != agent {
			continue
		}
		res = append(res, newCertificate(v))
	}

	return res
}

func keyTypeName(in KeyType) (string, error) {
	switch in {
	case KeyType_KEY_TYPE_ECDSA:
		return "ecdsa", nil
	case KeyType_KEY_TYPE_RSA:
		return "rsa", nil
	default:
		return "", connect.NewError(connect.CodeInvalidArgument, xerrors.Newf("dashboard: unknown key type %s", in))
	}
}
