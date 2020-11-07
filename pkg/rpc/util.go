package rpc

import (
	"github.com/golang/protobuf/ptypes"

	"go.f110.dev/heimdallr/pkg/database"
)

func DatabaseUserToRPCUser(in *database.User) *UserItem {
	t := UserType_NORMAL
	switch in.Type {
	case database.UserTypeServiceAccount:
		t = UserType_SERVICE_ACCOUNT
	}
	maintainRoles := make([]string, 0, len(in.MaintainRoles))
	for v := range in.MaintainRoles {
		maintainRoles = append(maintainRoles, v)
	}

	return &UserItem{
		Id:            in.Id,
		Roles:         in.Roles,
		LoginName:     in.LoginName,
		MaintainRoles: maintainRoles,
		Type:          t,
		Admin:         in.Admin,
		Comment:       in.Comment,
	}
}

func DatabaseCertToRPCCert(in *database.SignedCertificate) *CertItem {
	issuedAt, err := ptypes.TimestampProto(in.IssuedAt)
	if err != nil {
		return nil
	}

	return &CertItem{
		SerialNumber: in.Certificate.SerialNumber.Bytes(),
		CommonName:   in.Certificate.Subject.CommonName,
		IssuedAt:     issuedAt,
		Agent:        in.Agent,
		Comment:      in.Comment,
		HasP12:       in.P12 != nil && len(in.P12) > 0,
	}
}

func DatabaseCertToRPCCertWithByte(in *database.SignedCertificate) *CertItem {
	c := DatabaseCertToRPCCert(in)
	c.Certificate = in.Certificate.Raw
	c.P12 = in.P12
	c.HasP12 = in.P12 != nil && len(in.P12) > 0
	return c
}

func DatabaseRevokedCertToRPCCert(in *database.RevokedCertificate) *CertItem {
	issuedAt, err := ptypes.TimestampProto(in.IssuedAt)
	if err != nil {
		return nil
	}
	revokedAt, err := ptypes.TimestampProto(in.RevokedAt)
	if err != nil {
		return nil
	}

	return &CertItem{
		SerialNumber: in.SerialNumber.Bytes(),
		CommonName:   in.CommonName,
		Comment:      in.Comment,
		Agent:        in.Agent,
		IssuedAt:     issuedAt,
		RevokedAt:    revokedAt,
	}
}
