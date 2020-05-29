package cert

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"

	"golang.org/x/xerrors"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
)

var ErrCertificateNotFound = errors.New("cert: certificate not found")

type CertificateAuthority struct {
	db database.CertificateAuthority
	ca *config.CertificateAuthority
}

func NewCertificateAuthority(db database.CertificateAuthority, ca *config.CertificateAuthority) *CertificateAuthority {
	return &CertificateAuthority{db: db, ca: ca}
}

func (ca *CertificateAuthority) SignCertificateRequest(ctx context.Context, csr *x509.CertificateRequest, comment string, forAgent bool) (*database.SignedCertificate, error) {
	signedCert, err := SigningCertificateRequest(csr, ca.ca)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	obj := &database.SignedCertificate{
		Certificate: signedCert,
		IssuedAt:    time.Now(),
		Comment:     comment,
		Agent:       forAgent,
	}
	err = ca.db.SetSignedCertificate(ctx, obj)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return obj, nil
}

func (ca *CertificateAuthority) Revoke(ctx context.Context, certificate *database.SignedCertificate) error {
	err := ca.db.SetRevokedCertificate(ctx, &database.RevokedCertificate{
		CommonName:   certificate.Certificate.Subject.CommonName,
		SerialNumber: certificate.Certificate.SerialNumber,
		IssuedAt:     certificate.IssuedAt,
		RevokedAt:    time.Now(),
		Comment:      certificate.Comment,
		Agent:        certificate.Agent,
	})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (ca *CertificateAuthority) NewClientCertificate(ctx context.Context, name, keyType string, keyBits int, password, comment string) (*database.SignedCertificate, error) {
	return ca.newClientCertificate(ctx, name, keyType, keyBits, password, comment, false)
}

func (ca *CertificateAuthority) NewAgentCertificate(ctx context.Context, name, password, comment string) (*database.SignedCertificate, error) {
	return ca.newClientCertificate(ctx, name, database.DefaultPrivateKeyType, database.DefaultPrivateKeyBits, password, comment, true)

}

func (ca *CertificateAuthority) NewServerCertificate(commonName string) (*x509.Certificate, crypto.PrivateKey, error) {
	// TODO: Should use a serial key which created by database.CertificateAuthority
	certificate, privateKey, err := GenerateServerCertificate(ca.ca.Certificate, ca.ca.PrivateKey, []string{commonName})
	if err != nil {
		return nil, nil, xerrors.Errorf(": %w", err)
	}

	// TODO: Store to database
	return certificate, privateKey, nil
}

func (ca *CertificateAuthority) GetSignedCertificates(ctx context.Context) ([]*database.SignedCertificate, error) {
	certificates, err := ca.db.GetSignedCertificate(ctx, nil)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return certificates, nil
}

func (ca *CertificateAuthority) GetSignedCertificate(ctx context.Context, serial *big.Int) (*database.SignedCertificate, error) {
	certificates, err := ca.db.GetSignedCertificate(ctx, serial)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if len(certificates) == 0 {
		return nil, xerrors.Errorf(": %w", ErrCertificateNotFound)
	}
	if len(certificates) > 1 {
		logger.Log.Warn("Found multiple certificates. probably database is broken.")
	}

	return certificates[0], nil
}

func (ca *CertificateAuthority) GetRevokedCertificates(ctx context.Context) ([]*database.RevokedCertificate, error) {
	return ca.db.GetRevokedCertificate(ctx, nil)
}

func (ca *CertificateAuthority) WatchRevokeCertificate() chan *database.RevokedCertificate {
	return ca.db.WatchRevokeCertificate()
}

func (ca *CertificateAuthority) newClientCertificate(ctx context.Context, name, keyType string, keyBits int, password, comment string, agent bool) (*database.SignedCertificate, error) {
	serial, err := ca.db.NewSerialNumber(ctx)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	data, clientCert, err := CreateNewCertificateForClient(
		pkix.Name{
			Organization:       []string{ca.ca.Organization},
			OrganizationalUnit: []string{ca.ca.OrganizationUnit},
			Country:            []string{ca.ca.Country},
			CommonName:         name,
		},
		serial,
		keyType,
		keyBits,
		password,
		ca.ca,
	)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	signed := &database.SignedCertificate{
		Certificate: clientCert,
		P12:         data,
		IssuedAt:    time.Now(),
		Comment:     comment,
		Agent:       agent,
	}
	if err := ca.db.SetSignedCertificate(ctx, signed); err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return signed, nil
}
