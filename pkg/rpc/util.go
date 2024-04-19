package rpc

import (
	"google.golang.org/protobuf/types/known/timestamppb"

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

	lastLogin := timestamppb.New(in.LastLogin)
	return &UserItem{
		Id:            in.Id,
		Roles:         in.Roles,
		LoginName:     in.LoginName,
		MaintainRoles: maintainRoles,
		Type:          t,
		Admin:         in.Admin,
		Comment:       in.Comment,
		LastLogin:     lastLogin,
	}
}

func DatabaseCertToRPCCert(in *database.SignedCertificate) *CertItem {
	issuedAt := timestamppb.New(in.IssuedAt)

	return &CertItem{
		SerialNumber: in.Certificate.SerialNumber.Bytes(),
		CommonName:   in.Certificate.Subject.CommonName,
		IssuedAt:     issuedAt,
		Agent:        in.Agent,
		Device:       in.Device,
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
	issuedAt := timestamppb.New(in.IssuedAt)
	revokedAt := timestamppb.New(in.RevokedAt)

	return &CertItem{
		SerialNumber: in.SerialNumber.Bytes(),
		CommonName:   in.CommonName,
		Comment:      in.Comment,
		Agent:        in.Agent,
		Device:       in.Device,
		IssuedAt:     issuedAt,
		RevokedAt:    revokedAt,
	}
}
