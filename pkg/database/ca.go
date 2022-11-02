package database

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/gob"
	"math/big"
	"time"
)

const (
	DefaultPrivateKeyType = "ecdsa"
	DefaultPrivateKeyBits = 256
)

func init() {
	gob.Register(ecdsa.PublicKey{})
	gob.Register(rsa.PrivateKey{})
	gob.Register(rsa.PublicKey{})
	gob.Register(elliptic.P256())
}

type CertificateAuthority interface {
	// GetSignedCertificate returns a list of SignedCertificate.
	// You want to get a specify SignedCertificate then also passed the serial number.
	// You want to get all SignedCertificate then passed the nil to serialNumber.
	GetSignedCertificate(ctx context.Context, serialNumber *big.Int) ([]*SignedCertificate, error)
	// GetRevokedCertificate returns a list of RevokedCertificate.
	// An interface of this method is the same as GetSignedCertificate.
	GetRevokedCertificate(ctx context.Context, serialNumber *big.Int) ([]*RevokedCertificate, error)
	SetSignedCertificate(ctx context.Context, certificate *SignedCertificate) error
	SetRevokedCertificate(ctx context.Context, certificate *RevokedCertificate) error
	WatchRevokeCertificate() chan struct{}
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

func ParseSignedCertificate(b []byte) (*SignedCertificate, error) {
	signedCertificate := &SignedCertificate{}
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(signedCertificate); err != nil {
		return nil, err
	}

	return signedCertificate, nil
}

func (s *SignedCertificate) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	n := &SignedCertificate{}
	*n = *s
	dc := &x509.Certificate{}
	*dc = *s.Certificate
	dc.PublicKey = nil
	dc.PublicKeyAlgorithm = 0
	n.Certificate = dc
	if err := gob.NewEncoder(buf).Encode(n); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
