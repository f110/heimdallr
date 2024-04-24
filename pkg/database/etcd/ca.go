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

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.f110.dev/xerrors"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/database"
)

type CA struct {
	cache  *Cache
	client *clientv3.Client
}

var _ database.CertificateAuthority = &CA{}

func init() {
	gob.Register(ecdsa.PublicKey{})
	gob.Register(elliptic.P256())
	gob.Register(rsa.PrivateKey{})
	gob.Register(rsa.PublicKey{})
}

func NewCA(client *clientv3.Client) *CA {
	ca := &CA{client: client, cache: NewCache(client, "ca/revoke/", nil)}
	ca.cache.Start(context.Background())

	return ca
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
		return nil, xerrors.WithStack(err)
	}
	if res.Count == 0 {
		return nil, nil
	}

	signedCertificates := make([]*database.SignedCertificate, 0, res.Count)
	for _, v := range res.Kvs {
		signedCertificate, err := database.ParseSignedCertificate(v.Value)
		if err != nil {
			return nil, xerrors.WithStack(err)
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
		return nil, xerrors.WithStack(err)
	}
	if res.Count == 0 {
		return nil, nil
	}

	revokedCertificates := make([]*database.RevokedCertificate, 0, res.Count)
	for _, v := range res.Kvs {
		revokedCertificate := &database.RevokedCertificate{}
		if err := gob.NewDecoder(bytes.NewReader(v.Value)).Decode(revokedCertificate); err != nil {
			return nil, xerrors.WithStack(err)
		}
		revokedCertificates = append(revokedCertificates, revokedCertificate)
	}

	return revokedCertificates, nil
}

func (c *CA) SetRevokedCertificate(ctx context.Context, certificate *database.RevokedCertificate) error {
	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(certificate)
	if err != nil {
		return xerrors.WithStack(err)
	}

	key := fmt.Sprintf("ca/revoke/%x", certificate.SerialNumber)
	res, err := c.client.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(key), "=", 0)).
		Then(clientv3.OpPut(key, buf.String())).
		Commit()
	if err != nil {
		return xerrors.WithStack(err)
	}
	if !res.Succeeded {
		return xerrors.New("etcd: failed revoke certificate")
	}

	_, err = c.client.Delete(ctx, fmt.Sprintf("ca/signed_cert/%x", certificate.SerialNumber))
	if err != nil {
		return xerrors.WithStack(err)
	}

	return nil
}

func (c *CA) SetSignedCertificate(ctx context.Context, certificate *database.SignedCertificate) error {
	buf, err := certificate.Marshal()
	if err != nil {
		return err
	}
	_, err = c.client.Put(ctx, fmt.Sprintf("ca/signed_cert/%x", certificate.Certificate.SerialNumber), string(buf))
	if err != nil {
		return xerrors.WithStack(err)
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
			return nil, err
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

func (c *CA) WatchRevokeCertificate() chan struct{} {
	return c.cache.Notify()
}

func (c *CA) Close() {
	c.cache.Close()
}
