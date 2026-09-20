package dashboard

import (
	"context"
	"math/big"

	"connectrpc.com/connect"
	"go.f110.dev/xerrors"
	"google.golang.org/protobuf/types/known/timestamppb"

	"go.f110.dev/heimdallr/pkg/rpc"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
)

type service struct {
	rpcClient *rpcclient.ClientWithUserToken
}

// client returns a client that calls the rpc server on behalf of the user who sent the request.
func (s *service) client(ctx context.Context) *rpcclient.ClientWithUserToken {
	token, _ := ctx.Value(UserTokenKey).(string)
	return s.rpcClient.WithToken(token)
}

func verifiedUserId(ctx context.Context) (string, error) {
	userId, ok := ctx.Value(VerifiedUserIdKey).(string)
	if !ok {
		return "", connect.NewError(connect.CodeInternal, xerrors.New("dashboard: the request is not verified"))
	}

	return userId, nil
}

func serialNumberText(b []byte) string {
	serialNumber := big.NewInt(0)
	serialNumber.SetBytes(b)

	return serialNumber.Text(16)
}

func parseSerialNumber(s string) (*big.Int, error) {
	i, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, connect.NewError(connect.CodeInvalidArgument, xerrors.Newf("dashboard: %s is not a serial number", s))
	}

	return i, nil
}

func newCertificate(in *rpc.CertItem) *Certificate {
	return &Certificate{
		SerialNumber: serialNumberText(in.SerialNumber),
		CommonName:   in.CommonName,
		IssuedAt:     in.IssuedAt,
		RevokedAt:    in.RevokedAt,
		Comment:      in.Comment,
		HasP12:       in.HasP12 || len(in.P12) > 0,
	}
}

func newBackend(in *rpc.BackendItem) *Backend {
	return &Backend{
		Name:        in.Name,
		Host:        in.Host,
		Description: in.Description,
	}
}

func newUserType(in rpc.UserType) UserType {
	switch in {
	case rpc.UserType_NORMAL:
		return UserType_USER_TYPE_NORMAL
	case rpc.UserType_SERVICE_ACCOUNT:
		return UserType_USER_TYPE_SERVICE_ACCOUNT
	default:
		return UserType_USER_TYPE_UNSPECIFIED
	}
}

func newUser(in *rpc.UserItem) *User {
	return &User{
		Id:            in.Id,
		Type:          newUserType(in.Type),
		Roles:         in.Roles,
		MaintainRoles: in.MaintainRoles,
		Admin:         in.Admin,
		Comment:       in.Comment,
		LoginName:     in.LoginName,
		LastLogin:     in.LastLogin,
	}
}

func newAccessToken(in *rpc.AccessTokenItem) *AccessToken {
	return &AccessToken{
		Name:     in.Name,
		Issuer:   in.Issuer,
		IssuedAt: in.IssuedAt,
	}
}

func newAgent(in *rpc.Agent) *Agent {
	return &Agent{
		Name:        in.Name,
		FromAddr:    in.FromAddr,
		ConnectedAt: in.ConnectedAt,
	}
}

func timestampSeconds(t *timestamppb.Timestamp) int64 {
	if t == nil {
		return 0
	}

	return t.Seconds
}
