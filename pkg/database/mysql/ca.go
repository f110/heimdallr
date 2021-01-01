package mysql

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"math/big"
	"sync"
	"time"

	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/database/mysql/dao"
	"go.f110.dev/heimdallr/pkg/database/mysql/entity"
)

type CA struct {
	dao *dao.Repository

	mu sync.Mutex
	ch []chan *database.RevokedCertificate

	startWatchChOnce sync.Once
	lastWatchTime    time.Time
	lastWatchStatus  bool
}

var _ database.CertificateAuthority = &CA{}

func NewCA(dao *dao.Repository) *CA {
	return &CA{dao: dao}
}

func (ca *CA) GetSignedCertificate(ctx context.Context, serialNumber *big.Int) ([]*database.SignedCertificate, error) {
	var certs []*entity.SignedCertificate
	if serialNumber == nil {
		c, err := ca.dao.SignedCertificate.ListAll(ctx)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		certs = c
	} else {
		sn, err := ca.dao.SerialNumber.SelectSerialNumber(ctx, serialNumber.Bytes())
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}

		c, err := ca.dao.SignedCertificate.ListSerialNumber(ctx, sn.Id)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		certs = c
	}

	result := make([]*database.SignedCertificate, len(certs))
	for i, v := range certs {
		c, err := x509.ParseCertificate(v.Certificate)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}

		result[i] = &database.SignedCertificate{
			Certificate: c,
			Comment:     v.Comment,
			P12:         v.P12,
			IssuedAt:    v.IssuedAt,
			Agent:       v.Agent,
		}
	}

	return result, nil
}

func (ca *CA) GetRevokedCertificate(ctx context.Context, serialNumber *big.Int) ([]*database.RevokedCertificate, error) {
	var certs []*entity.RevokedCertificate
	if serialNumber == nil {
		c, err := ca.dao.RevokedCertificate.ListAll(ctx)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, xerrors.Errorf(": %w", err)
		}
		certs = c
	} else {
		c, err := ca.dao.RevokedCertificate.ListSerialNumber(ctx, serialNumber.Bytes())
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		certs = c
	}

	result := make([]*database.RevokedCertificate, len(certs))
	for i, v := range certs {
		sn := big.NewInt(0)
		sn.SetBytes(v.SerialNumber)

		result[i] = &database.RevokedCertificate{
			CommonName:   v.CommonName,
			SerialNumber: sn,
			IssuedAt:     v.IssuedAt,
			RevokedAt:    v.RevokedAt,
			Agent:        v.Agent,
			Device:       v.Device,
			Comment:      v.Comment,
		}
	}

	return result, nil
}

func (ca *CA) SetSignedCertificate(ctx context.Context, certificate *database.SignedCertificate) error {
	sn, err := ca.dao.SerialNumber.SelectSerialNumber(ctx, certificate.Certificate.SerialNumber.Bytes())
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	v := &entity.SignedCertificate{
		Certificate:    certificate.Certificate.Raw,
		SerialNumberId: sn.Id,
		P12:            certificate.P12,
		Agent:          certificate.Agent,
		Comment:        certificate.Comment,
		IssuedAt:       certificate.IssuedAt,
	}
	_, err = ca.dao.SignedCertificate.Create(ctx, v)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (ca *CA) SetRevokedCertificate(ctx context.Context, certificate *database.RevokedCertificate) error {
	sn, err := ca.dao.SerialNumber.SelectSerialNumber(ctx, certificate.SerialNumber.Bytes())
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	certs, err := ca.dao.SignedCertificate.ListSerialNumber(ctx, sn.Id)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if len(certs) != 1 {
		return sql.ErrNoRows
	}
	cert := certs[0]

	v := &entity.RevokedCertificate{
		CommonName:   certificate.CommonName,
		SerialNumber: certificate.SerialNumber.Bytes(),
		Agent:        certificate.Agent,
		Comment:      certificate.Comment,
		RevokedAt:    certificate.RevokedAt,
		IssuedAt:     certificate.IssuedAt,
	}

	err = ca.dao.RevokedCertificate.Tx(ctx, func(tx *sql.Tx) error {
		_, err = ca.dao.RevokedCertificate.Create(ctx, v, dao.WithTx(tx))
		if err != nil {
			return xerrors.Errorf(": %w", err)
		}

		if err := ca.dao.SignedCertificate.Delete(ctx, cert.Id, dao.WithTx(tx)); err != nil {
			return xerrors.Errorf(": %w", err)
		}

		return nil
	})
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (ca *CA) WatchRevokeCertificate() chan *database.RevokedCertificate {
	ch := make(chan *database.RevokedCertificate)
	ca.mu.Lock()
	defer ca.mu.Unlock()

	ca.startWatchChOnce.Do(func() {
		go ca.watchRevoke()
	})

	ca.ch = append(ca.ch, ch)
	return ch
}

func (ca *CA) NewSerialNumber(ctx context.Context) (*big.Int, error) {
	var serial *big.Int
	retry := 0
	for {
		if retry == 3 {
			return nil, xerrors.New("mysql: can't generate new serial number")
		}

		s, err := cert.NewSerialNumber()
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		serial = s
		_, err = ca.dao.SerialNumber.Create(ctx, &entity.SerialNumber{SerialNumber: s.Bytes()})
		if err != nil {
			retry++
			continue
		}

		break
	}

	return serial, nil
}

func (ca *CA) watchRevoke() {
	t := time.NewTicker(1 * time.Minute)
	for {
		select {
		case <-t.C:
			ca.checkRevokedCertificate()
		}
	}
}

func (ca *CA) checkRevokedCertificate() {
	now := time.Now()
	ctx, cancelFunc := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelFunc()

	revoked, err := ca.dao.RevokedCertificate.ListAll(ctx)
	if err != nil {
		ca.lastWatchStatus = false
		ca.lastWatchTime = now
		return
	}
	updated := make([]*entity.RevokedCertificate, 0)
	for _, v := range revoked {
		if v.CreatedAt.After(ca.lastWatchTime) {
			updated = append(updated, v)
		}
	}

	ca.mu.Lock()
	for _, v := range updated {
		sn := big.NewInt(0)
		sn.SetBytes(v.SerialNumber)
		rev := &database.RevokedCertificate{
			CommonName:   v.CommonName,
			SerialNumber: sn,
			IssuedAt:     v.IssuedAt,
			RevokedAt:    v.RevokedAt,
			Agent:        v.Agent,
			Device:       v.Device,
			Comment:      v.Comment,
		}

		for _, ch := range ca.ch {
			select {
			case ch <- rev:
			default:
			}
		}
	}
	ca.mu.Unlock()

	ca.lastWatchStatus = true
	ca.lastWatchTime = now
}
