package memory

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math"
	"math/big"
	"sync"
	"time"

	"golang.org/x/xerrors"

	"github.com/f110/lagrangian-proxy/pkg/cert"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/connector"
	"github.com/f110/lagrangian-proxy/pkg/database"
)

type CA struct {
	config *config.CertificateAuthority

	mu                  sync.Mutex
	signedCertificates  []*database.SignedCertificate
	revokedCertificates []*database.RevokedCertificate
}

var _ database.CertificateAuthority = &CA{}

func NewCA(config *config.CertificateAuthority) *CA {
	return &CA{
		config:              config,
		signedCertificates:  make([]*database.SignedCertificate, 0),
		revokedCertificates: make([]*database.RevokedCertificate, 0),
	}
}

func (c *CA) WatchRevokeCertificate() chan *database.RevokedCertificate {
	return nil
}

func (c *CA) GetSignedCertificates(_ context.Context) ([]*database.SignedCertificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.signedCertificates, nil
}

func (c *CA) GetSignedCertificate(_ context.Context, serial *big.Int) (*database.SignedCertificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, v := range c.signedCertificates {
		if v.Certificate.SerialNumber.Cmp(serial) == 0 {
			return v, nil
		}
	}

	return nil, xerrors.New("etcd: not found certificate")
}

func (c *CA) GetRevokedCertificates() []*database.RevokedCertificate {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.revokedCertificates
}

func (c *CA) NewClientCertificate(ctx context.Context, name, password, comment string) ([]byte, error) {
	return c.generateClientCertificate(ctx, name, password, comment, false)
}

func (c *CA) NewAgentCertificate(ctx context.Context, name, comment string) ([]byte, error) {
	return c.generateClientCertificate(ctx, name, connector.DefaultCertificatePassword, comment, true)
}

func (c *CA) SignCertificateRequest(ctx context.Context, csr *x509.CertificateRequest, comment string, agent bool) ([]byte, error) {
	signedCert, err := cert.SigningCertificateRequest(csr, c.config)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	if err := c.SetSignedCertificate(&database.SignedCertificate{
		Certificate: signedCert,
		IssuedAt:    time.Now(),
		Comment:     comment,
		Agent:       agent,
	}); err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	return signedCert.Raw, nil
}

func (c *CA) generateClientCertificate(_ context.Context, name, password, comment string, agent bool) ([]byte, error) {
	serial, err := c.newSerialNumber()
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	data, clientCert, err := cert.CreateNewCertificateForClient(
		pkix.Name{
			Organization:       []string{c.config.Organization},
			OrganizationalUnit: []string{c.config.OrganizationUnit},
			Country:            []string{c.config.Country},
			CommonName:         name,
		},
		serial,
		password,
		c.config,
	)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	if err := c.SetSignedCertificate(&database.SignedCertificate{
		Certificate: clientCert,
		P12:         data,
		IssuedAt:    time.Now(),
		Comment:     comment,
		Agent:       agent,
	}); err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	return data, nil
}

func (c *CA) NewServerCertificate(commonName string) (*x509.Certificate, crypto.PrivateKey, error) {
	certBytes, privateKey, err := cert.GenerateServerCertificate(c.config.Certificate, c.config.PrivateKey, []string{commonName})
	if err != nil {
		return nil, nil, xerrors.Errorf(": %v", err)
	}
	certificate, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, xerrors.Errorf(": %v", err)
	}
	return certificate, privateKey, nil
}

func (c *CA) Revoke(_ context.Context, certificate *database.SignedCertificate) error {
	revokeCertificate := &database.RevokedCertificate{
		CommonName:   certificate.Certificate.Subject.CommonName,
		SerialNumber: certificate.Certificate.SerialNumber,
		IssuedAt:     certificate.IssuedAt,
		RevokedAt:    time.Now(),
		Comment:      certificate.Comment,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.revokedCertificates = append(c.revokedCertificates, revokeCertificate)
	for i, v := range c.signedCertificates {
		if v.Certificate.SerialNumber.Cmp(certificate.Certificate.SerialNumber) == 0 {
			c.signedCertificates = append(c.signedCertificates[:i], c.signedCertificates[i+1:]...)
		}
	}

	return nil
}

func (c *CA) SetSignedCertificate(certificate *database.SignedCertificate) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.signedCertificates = append(c.signedCertificates, certificate)
	return nil
}

func (c *CA) newSerialNumber() (*big.Int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var serial *big.Int
	retry := 0
Retry:
	for {
		if retry == 3 {
			return nil, xerrors.New("memory: can not generate new serial number")
		}

		s, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
		if err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}
		serial = s

		for _, v := range c.signedCertificates {
			if v.Certificate.SerialNumber.Int64() == serial.Int64() {
				retry++
				continue Retry
			}
		}
		break
	}

	return serial, nil
}
