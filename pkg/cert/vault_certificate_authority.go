package cert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"time"

	"go.f110.dev/xerrors"
	"software.sslmate.com/src/go-pkcs12"

	"go.f110.dev/heimdallr/pkg/cert/vault"
	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
)

type vaultCertificateAuthority struct {
	db     database.CertificateAuthority
	client *vault.Client
}

func newVaultCertificateAuthority(db database.CertificateAuthority, conf *configv2.CertificateAuthorityVault) (*vaultCertificateAuthority, error) {
	c, err := vault.NewClient(conf.Addr, conf.Token, conf.MountPath, conf.Role)
	if err != nil {
		return nil, err
	}

	return &vaultCertificateAuthority{db: db, client: c}, nil
}

func (ca *vaultCertificateAuthority) SignCertificateRequest(
	ctx context.Context,
	csr *x509.CertificateRequest,
	comment string,
	forAgent, forDevice bool,
) (*database.SignedCertificate, error) {
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

func (ca *vaultCertificateAuthority) SignCertificateRequestWithoutRecord(ctx context.Context, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Bytes: csr.Raw, Type: "CERTIFICATE REQUEST"}); err != nil {
		return nil, xerrors.WithStack(err)
	}
	signedCert, err := ca.client.Sign(ctx, csr)
	if err != nil {
		return nil, err
	}

	return signedCert, nil
}

func (ca *vaultCertificateAuthority) Revoke(ctx context.Context, cert *database.SignedCertificate) error {
	err := ca.client.Revoke(ctx, cert.Certificate)
	if err != nil {
		return err
	}

	err = ca.db.SetRevokedCertificate(ctx, &database.RevokedCertificate{
		CommonName:   cert.Certificate.Subject.CommonName,
		SerialNumber: cert.Certificate.SerialNumber,
		IssuedAt:     cert.IssuedAt,
		RevokedAt:    time.Now(),
		Comment:      cert.Comment,
		Agent:        cert.Agent,
		Device:       cert.Device,
	})
	if err != nil {
		return err
	}

	return nil
}

func (ca *vaultCertificateAuthority) NewClientCertificate(
	ctx context.Context,
	name, _ string,
	_ int,
	password, comment string,
) (*database.SignedCertificate, error) {
	return ca.newClientCertificate(ctx, name, password, comment, false, false)
}

func (ca *vaultCertificateAuthority) NewAgentCertificate(
	ctx context.Context,
	name, password, comment string,
) (*database.SignedCertificate, error) {
	return ca.newClientCertificate(ctx, name, password, comment, true, false)
}

func (ca *vaultCertificateAuthority) newClientCertificate(
	ctx context.Context,
	name string,
	password, comment string,
	agent, device bool,
) (*database.SignedCertificate, error) {
	cert, privateKey, err := ca.client.GenerateCertificate(ctx, name, nil)
	if err != nil {
		return nil, err
	}
	caCert, err := ca.client.GetCACertificate(ctx)
	if err != nil {
		return nil, err
	}
	data, err := pkcs12.Encode(rand.Reader, privateKey, cert, []*x509.Certificate{caCert}, password)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	signed := &database.SignedCertificate{
		Certificate: cert,
		P12:         data,
		IssuedAt:    time.Now(),
		Comment:     comment,
		Agent:       agent,
		Device:      device,
	}
	err = ca.db.SetSignedCertificate(ctx, signed)
	if err != nil {
		return nil, err
	}

	return signed, nil
}

func (ca *vaultCertificateAuthority) NewServerCertificate(commonName string) (*x509.Certificate, crypto.PrivateKey, error) {
	cert, privateKey, err := ca.client.GenerateCertificate(context.TODO(), commonName, []string{commonName})
	if err != nil {
		return nil, nil, err
	}

	return cert, privateKey, nil
}

func (ca *vaultCertificateAuthority) GetSignedCertificates(ctx context.Context) ([]*database.SignedCertificate, error) {
	certificates, err := ca.db.GetSignedCertificate(ctx, nil)
	if err != nil {
		return nil, err
	}

	return certificates, nil
}

func (ca *vaultCertificateAuthority) GetSignedCertificate(
	ctx context.Context,
	serial *big.Int,
) (*database.SignedCertificate, error) {
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

func (ca *vaultCertificateAuthority) GetRevokedCertificates(ctx context.Context) ([]*database.RevokedCertificate, error) {
	return ca.db.GetRevokedCertificate(ctx, nil)
}

func (ca *vaultCertificateAuthority) WatchRevokeCertificate() chan struct{} {
	return ca.db.WatchRevokeCertificate()
}
