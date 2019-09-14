package memory

import (
	"context"
	"crypto/rand"
	"crypto/x509/pkix"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"golang.org/x/xerrors"
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

func (c *CA) GetSignedCertificates(ctx context.Context) ([]*database.SignedCertificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.signedCertificates, nil
}

func (c *CA) GetSignedCertificate(ctx context.Context, serial *big.Int) (*database.SignedCertificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, v := range c.signedCertificates {
		if v.Certificate.SerialNumber.Cmp(serial) == 0 {
			return v, nil
		}
	}

	return nil, xerrors.New("etcd: not found certificate")
}

func (c *CA) GetRevokedCertificates(ctx context.Context) []*database.RevokedCertificate {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.revokedCertificates
}

func (c *CA) NewClientCertificate(ctx context.Context, name, password, comment string) ([]byte, error) {
	serial, err := c.newSerialNumber(ctx)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	data, clientCert, err := database.CreateNewCertificateForClient(
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
	if err := c.SetSignedCertificate(ctx, &database.SignedCertificate{
		Certificate: clientCert,
		P12:         data,
		IssuedAt:    time.Now(),
		Comment:     comment,
	}); err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	return data, nil
}

func (c *CA) Revoke(ctx context.Context, certificate *database.SignedCertificate) error {
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

func (c *CA) SetSignedCertificate(ctx context.Context, certificate *database.SignedCertificate) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.signedCertificates = append(c.signedCertificates, certificate)
	return nil
}

func (c *CA) newSerialNumber(ctx context.Context) (*big.Int, error) {
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
