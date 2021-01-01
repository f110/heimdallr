package database

import (
	"context"
	"crypto/x509"
	"math/big"
	"time"
)

const (
	DefaultPrivateKeyType = "ecdsa"
	DefaultPrivateKeyBits = 256
)

type CertificateAuthority interface {
	// GetSignedCertificates returns a list of SignedCertificate.
	// You want to get a specify SignedCertificate then also passed the serial number.
	// You want to get all SignedCertificate then passed the nil to serialNumber.
	GetSignedCertificate(ctx context.Context, serialNumber *big.Int) ([]*SignedCertificate, error)
	// GetRevokedCertificate returns a list of RevokedCertificate.
	// An interface of this method is the same as GetSignedCertificate.
	GetRevokedCertificate(ctx context.Context, serialNumber *big.Int) ([]*RevokedCertificate, error)
	SetSignedCertificate(ctx context.Context, certificate *SignedCertificate) error
	SetRevokedCertificate(ctx context.Context, certificate *RevokedCertificate) error
	WatchRevokeCertificate() chan *RevokedCertificate
	NewSerialNumber(ctx context.Context) (*big.Int, error)
}

type SignedCertificate struct {
	Certificate *x509.Certificate
	P12         []byte
	IssuedAt    time.Time
	Agent       bool
	Device      bool
	Comment     string
}

type RevokedCertificate struct {
	CommonName   string
	SerialNumber *big.Int
	IssuedAt     time.Time
	RevokedAt    time.Time
	Agent        bool
	Device       bool
	Comment      string
}
