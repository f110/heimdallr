package memory

import (
	"context"
	"crypto/rand"
	"math"
	"math/big"
	"sync"

	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/config"
	"go.f110.dev/heimdallr/pkg/database"
)

type CA struct {
	config *config.CertificateAuthority

	mu                  sync.Mutex
	signedCertificates  []*database.SignedCertificate
	revokedCertificates []*database.RevokedCertificate
	watcher             []chan struct{}
}

var _ database.CertificateAuthority = &CA{}

func NewCA() *CA {
	return &CA{
		signedCertificates:  make([]*database.SignedCertificate, 0),
		revokedCertificates: make([]*database.RevokedCertificate, 0),
		watcher:             make([]chan struct{}, 0),
	}
}

func (c *CA) WatchRevokeCertificate() chan struct{} {
	ch := make(chan struct{}, 1)
	c.mu.Lock()
	c.watcher = append(c.watcher, ch)
	c.mu.Unlock()

	return ch
}

func (c *CA) GetSignedCertificate(_ context.Context, serial *big.Int) ([]*database.SignedCertificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if serial != nil {
		for _, v := range c.signedCertificates {
			if v.Certificate.SerialNumber.Cmp(serial) == 0 {
				return []*database.SignedCertificate{v}, nil
			}
		}

		return nil, xerrors.New("memory: certificate not found")
	}

	return c.signedCertificates, nil
}

func (c *CA) GetRevokedCertificate(_ context.Context, serial *big.Int) ([]*database.RevokedCertificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if serial != nil {
		for _, v := range c.revokedCertificates {
			if v.SerialNumber.Cmp(serial) == 0 {
				return []*database.RevokedCertificate{v}, nil
			}
		}

		return nil, xerrors.New("memory: the revoked certificate not found")
	}

	return c.revokedCertificates, nil
}

func (c *CA) SetRevokedCertificate(_ context.Context, certificate *database.RevokedCertificate) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.revokedCertificates = append(c.revokedCertificates, certificate)
	for i, v := range c.signedCertificates {
		if v.Certificate.SerialNumber.Cmp(certificate.SerialNumber) == 0 {
			c.signedCertificates = append(c.signedCertificates[:i], c.signedCertificates[i+1:]...)
		}
	}

	for i, v := range c.watcher {
		select {
		case v <- struct{}{}:
		default:
			c.watcher = append(c.watcher[:i], c.watcher[i+1:]...)
		}
	}

	return nil
}

func (c *CA) SetSignedCertificate(_ context.Context, certificate *database.SignedCertificate) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.signedCertificates = append(c.signedCertificates, certificate)
	return nil
}

func (c *CA) NewSerialNumber(_ context.Context) (*big.Int, error) {
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
