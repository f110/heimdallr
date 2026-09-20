package dashboard

import (
	"context"
	"sort"

	"connectrpc.com/connect"
	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
)

type MeService struct {
	service
}

var _ MeServiceHandler = &MeService{}

func NewMeService(c *rpcclient.ClientWithUserToken) *MeService {
	return &MeService{service: service{rpcClient: c}}
}

func (s *MeService) GetMe(ctx context.Context, _ *connect.Request[GetMeRequest]) (*connect.Response[GetMeResponse], error) {
	userId, err := verifiedUserId(ctx)
	if err != nil {
		return nil, err
	}
	client := s.client(ctx)

	signed, err := client.ListCert(ctx, rpcclient.CommonName(userId), rpcclient.IsDevice())
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	devices := make([]*Certificate, 0, len(signed))
	for _, v := range signed {
		devices = append(devices, newCertificate(v))
	}
	sort.Slice(devices, func(i, j int) bool {
		return timestampSeconds(devices[i].IssuedAt) > timestampSeconds(devices[j].IssuedAt)
	})

	backends, err := client.GetBackends(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	services := make([]*Backend, 0, len(backends))
	for _, v := range backends {
		services = append(services, newBackend(v))
	}
	sort.Slice(services, func(i, j int) bool {
		return services[i].Name < services[j].Name
	})

	return connect.NewResponse(&GetMeResponse{Devices: devices, Backends: services}), nil
}

func (s *MeService) AddDevice(ctx context.Context, req *connect.Request[AddDeviceRequest]) (*connect.Response[AddDeviceResponse], error) {
	userId, err := verifiedUserId(ctx)
	if err != nil {
		return nil, err
	}
	if req.Msg.Csr == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, xerrors.New("dashboard: csr is empty"))
	}

	// The common name is always overridden by the subject of the verified token so that a user
	// can not issue a certificate for someone else.
	_, err = s.client(ctx).NewCertByCSR(ctx, req.Msg.Csr,
		rpcclient.OverrideCommonName(userId),
		rpcclient.IsDevice(),
		rpcclient.Comment(req.Msg.Name),
	)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return connect.NewResponse(&AddDeviceResponse{}), nil
}
