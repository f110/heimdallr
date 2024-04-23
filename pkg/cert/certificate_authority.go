package cert

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"

	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
)

var ErrCertificateNotFound = errors.New("cert: certificate not found")

type CertificateAuthority struct {
	db database.CertificateAuthority
	ca *configv2.CertificateAuthority

	vault *vaultCertificateAuthority
}

func NewCertificateAuthority(db database.CertificateAuthority, ca *configv2.CertificateAuthority) (*CertificateAuthority, error) {
	v := &CertificateAuthority{db: db, ca: ca}

	if ca.Vault != nil {
		vaultCA, err := newVaultCertificateAuthority(db, ca.Vault)
		if err != nil {
			return nil, err
		}
		v.vault = vaultCA
	}
	return v, nil
}

func (ca *CertificateAuthority) SignCertificateRequest(ctx context.Context, csr *x509.CertificateRequest, comment string, forAgent, forDevice bool) (*database.SignedCertificate, error) {
	if ca.vault != nil {
		return ca.vault.SignCertificateRequest(ctx, csr, comment, forAgent, forDevice)
	}

	signedCert, err := ca.SignCertificateRequestWithoutRecord(ctx, csr)
	if err != nil {
		return nil, err
	}

	obj := &database.SignedCertificate{
		Certificate: signedCert,
		IssuedAt:    time.Now(),
		Comment:     comment,
		Agent:       forAgent,
		Device:      forDevice,
	}
	err = ca.db.SetSignedCertificate(ctx, obj)
	if err != nil {
		return nil, err
	}

	return obj, nil
}

func (ca *CertificateAuthority) SignCertificateRequestWithoutRecord(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	if ca.vault != nil {
		return ca.vault.SignCertificateRequestWithoutRecord(ctx, csr)
	}

	signedCert, err := SigningCertificateRequest(csr, ca.ca)
	if err != nil {
		return nil, err
	}

	return signedCert, nil
}

func (ca *CertificateAuthority) Revoke(ctx context.Context, certificate *database.SignedCertificate) error {
	if ca.vault != nil {
		return ca.vault.Revoke(ctx, certificate)
	}

	err := ca.db.SetRevokedCertificate(ctx, &database.RevokedCertificate{
		CommonName:   certificate.Certificate.Subject.CommonName,
		SerialNumber: certificate.Certificate.SerialNumber,
		IssuedAt:     certificate.IssuedAt,
		RevokedAt:    time.Now(),
		Comment:      certificate.Comment,
		Agent:        certificate.Agent,
		Device:       certificate.Device,
	})
	if err != nil {
		return err
	}

	return nil
}

func (ca *CertificateAuthority) NewClientCertificate(ctx context.Context, name, keyType string, keyBits int, password, comment string) (*database.SignedCertificate, error) {
	if ca.vault != nil {
		return ca.vault.NewClientCertificate(ctx, name, keyType, keyBits, password, comment)
	}

	return ca.newClientCertificate(ctx, name, keyType, keyBits, password, comment, false, false)
}

func (ca *CertificateAuthority) NewAgentCertificate(ctx context.Context, name, password, comment string) (*database.SignedCertificate, error) {
	if ca.vault != nil {
		return ca.vault.NewAgentCertificate(ctx, name, password, comment)
	}

	return ca.newClientCertificate(ctx, name, database.DefaultPrivateKeyType, database.DefaultPrivateKeyBits, password, comment, true, false)

}

func (ca *CertificateAuthority) NewServerCertificate(commonName string) (*x509.Certificate, crypto.PrivateKey, error) {
	if ca.vault != nil {
		return ca.vault.NewServerCertificate(commonName)
	}

	// TODO: Should use a serial key which created by database.CertificateAuthority
	certificate, privateKey, err := GenerateServerCertificate(ca.ca.Certificate, ca.ca.Local.PrivateKey, []string{commonName})
	if err != nil {
		return nil, nil, err
	}

	// TODO: Store to database
	return certificate, privateKey, nil
}

func (ca *CertificateAuthority) GetSignedCertificates(ctx context.Context) ([]*database.SignedCertificate, error) {
	if ca.vault != nil {
		return ca.vault.GetSignedCertificates(ctx)
	}

	certificates, err := ca.db.GetSignedCertificate(ctx, nil)
	if err != nil {
		return nil, err
	}

	return certificates, nil
}

func (ca *CertificateAuthority) GetSignedCertificate(ctx context.Context, serial *big.Int) (*database.SignedCertificate, error) {
	if ca.vault != nil {
		return ca.vault.GetSignedCertificate(ctx, serial)
	}

	certificates, err := ca.db.GetSignedCertificate(ctx, serial)
	if err != nil {
		return nil, err
	}
	if len(certificates) == 0 {
		return nil, xerrors.WithStack(ErrCertificateNotFound)
	}
	if len(certificates) > 1 {
		logger.Log.Warn("Found multiple certificates. probably database is broken.")
	}

	return certificates[0], nil
}

func (ca *CertificateAuthority) GetRevokedCertificates(ctx context.Context) ([]*database.RevokedCertificate, error) {
	if ca.vault != nil {
		return ca.vault.GetRevokedCertificates(ctx)
	}

	return ca.db.GetRevokedCertificate(ctx, nil)
}

func (ca *CertificateAuthority) WatchRevokeCertificate() chan struct{} {
	if ca.vault != nil {
		return ca.vault.WatchRevokeCertificate()
	}

	return ca.db.WatchRevokeCertificate()
}

func (ca *CertificateAuthority) newClientCertificate(ctx context.Context, name, keyType string, keyBits int, password, comment string, agent, device bool) (*database.SignedCertificate, error) {
	serial, err := ca.db.NewSerialNumber(ctx)
	if err != nil {
		return nil, err
	}
	data, clientCert, err := CreateNewCertificateForClient(
		pkix.Name{
			Organization:       []string{ca.ca.Local.Organization},
			OrganizationalUnit: []string{ca.ca.Local.OrganizationUnit},
			Country:            []string{ca.ca.Local.Country},
			CommonName:         name,
		},
		serial,
		keyType,
		keyBits,
		password,
		ca.ca,
	)
	if err != nil {
		return nil, err
	}

	signed := &database.SignedCertificate{
		Certificate: clientCert,
		P12:         data,
		IssuedAt:    time.Now(),
		Comment:     comment,
		Agent:       agent,
		Device:      device,
	}
	if err := ca.db.SetSignedCertificate(ctx, signed); err != nil {
		return nil, err
	}

	return signed, nil
}
