package etcd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/gob"
	"fmt"
	"math/big"
	"sync"

	"go.etcd.io/etcd/v3/clientv3"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/database"
	"go.f110.dev/heimdallr/pkg/logger"
)

type CA struct {
	client *clientv3.Client

	mu          sync.RWMutex
	revokedList []*database.RevokedCertificate

	wMu     sync.RWMutex
	watchCh []chan *database.RevokedCertificate
}

var _ database.CertificateAuthority = &CA{}

func init() {
	gob.Register(ecdsa.PublicKey{})
	gob.Register(elliptic.P256())
	gob.Register(rsa.PrivateKey{})
	gob.Register(rsa.PublicKey{})
}

func NewCA(ctx context.Context, client *clientv3.Client) (*CA, error) {
	res, err := client.Get(ctx, "ca/revoke/", clientv3.WithPrefix())
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	revoked := make([]*database.RevokedCertificate, 0, res.Count)
	for _, v := range res.Kvs {
		r := &database.RevokedCertificate{}
		err := gob.NewDecoder(bytes.NewReader(v.Value)).Decode(r)
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		revoked = append(revoked, r)
	}

	ca := &CA{client: client, revokedList: revoked}
	go ca.watchRevokeList(ctx, res.Header.Revision)
	return ca, nil
}

func (c *CA) GetSignedCertificate(ctx context.Context, serial *big.Int) ([]*database.SignedCertificate, error) {
	key := "ca/signed_cert/"
	var opt []clientv3.OpOption
	if serial != nil {
		key += fmt.Sprintf("%x", serial)
	} else {
		opt = append(opt, clientv3.WithPrefix())
	}
	res, err := c.client.Get(ctx, key, opt...)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if res.Count == 0 {
		return nil, nil
	}

	signedCertificates := make([]*database.SignedCertificate, 0, res.Count)
	for _, v := range res.Kvs {
		signedCertificate := &database.SignedCertificate{}
		if err := gob.NewDecoder(bytes.NewReader(v.Value)).Decode(signedCertificate); err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		signedCertificates = append(signedCertificates, signedCertificate)
	}

	return signedCertificates, nil
}

func (c *CA) GetRevokedCertificate(ctx context.Context, serial *big.Int) ([]*database.RevokedCertificate, error) {
	key := "ca/revoke/"
	var opt []clientv3.OpOption
	if serial != nil {
		key += fmt.Sprintf("%x", serial)
	} else {
		opt = append(opt, clientv3.WithPrefix())
	}
	res, err := c.client.Get(ctx, key, opt...)
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}
	if res.Count == 0 {
		return nil, nil
	}

	revokedCertificates := make([]*database.RevokedCertificate, 0, res.Count)
	for _, v := range res.Kvs {
		revokedCertificate := &database.RevokedCertificate{}
		if err := gob.NewDecoder(bytes.NewReader(v.Value)).Decode(revokedCertificate); err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		revokedCertificates = append(revokedCertificates, revokedCertificate)
	}

	return revokedCertificates, nil
}

func (c *CA) SetRevokedCertificate(ctx context.Context, certificate *database.RevokedCertificate) error {
	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(certificate)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	key := fmt.Sprintf("ca/revoke/%x", certificate.SerialNumber)
	res, err := c.client.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(key), "=", 0)).
		Then(clientv3.OpPut(key, buf.String())).
		Commit()
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	if !res.Succeeded {
		return xerrors.New("etcd: failed revoke certificate")
	}

	_, err = c.client.Delete(ctx, fmt.Sprintf("ca/signed_cert/%x", certificate.SerialNumber))
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (c *CA) SetSignedCertificate(ctx context.Context, certificate *database.SignedCertificate) error {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(certificate); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	_, err := c.client.Put(ctx, fmt.Sprintf("ca/signed_cert/%x", certificate.Certificate.SerialNumber), buf.String())
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (c *CA) NewSerialNumber(ctx context.Context) (*big.Int, error) {
	var serial *big.Int
	retry := 0
	for {
		if retry == 3 {
			return nil, xerrors.New("etcd: can't generate new serial number")
		}

		s, err := cert.NewSerialNumber()
		if err != nil {
			return nil, xerrors.Errorf(": %w", err)
		}
		serial = s

		key := fmt.Sprintf("ca/serialnumber/%x", serial)
		res, err := c.client.Txn(ctx).
			If(clientv3.Compare(clientv3.CreateRevision(key), "=", 0)).
			Then(clientv3.OpPut(key, serial.String())).
			Commit()
		if err != nil {
			retry++
			continue
		}
		if !res.Succeeded {
			retry++
			continue
		}
		break
	}

	return serial, nil
}

func (c *CA) WatchRevokeCertificate() chan *database.RevokedCertificate {
	ch := make(chan *database.RevokedCertificate)
	c.wMu.Lock()
	c.watchCh = append(c.watchCh, ch)
	c.wMu.Unlock()

	return ch
}

func (c *CA) watchRevokeList(ctx context.Context, revision int64) {
	logger.Log.Debug("Start watching revoke list")
	watchCh := c.client.Watch(ctx, "ca/revoke/", clientv3.WithPrefix(), clientv3.WithRev(revision))
	for {
		select {
		case res := <-watchCh:
			for _, event := range res.Events {
				if event.Type != clientv3.EventTypePut {
					continue
				}

				r := &database.RevokedCertificate{}
				err := gob.NewDecoder(bytes.NewReader(event.Kv.Value)).Decode(r)
				if err != nil {
					logger.Log.Warn("Failed parse revoked event", zap.Error(err))
					continue
				}

				c.mu.Lock()
				c.revokedList = append(c.revokedList, r)
				c.mu.Unlock()
				logger.Log.Debug("Add new revoked certificate", zap.String("serial", r.SerialNumber.Text(16)))

				c.wMu.Lock()
				for i, ch := range c.watchCh {
					select {
					case ch <- r:
					default:
						c.watchCh = append(c.watchCh[:i], c.watchCh[i+1:]...)
					}
				}
				c.wMu.Unlock()
			}
		case <-ctx.Done():
			return
		}
	}
}
