package etcd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/gob"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"golang.org/x/xerrors"
)

type CA struct {
	config *config.CertificateAuthority
	client *clientv3.Client
}

func init() {
	gob.Register(ecdsa.PublicKey{})
	gob.Register(elliptic.P256())
}

func NewCA(config *config.CertificateAuthority, client *clientv3.Client) *CA {
	return &CA{config: config, client: client}
}

func (c *CA) GetSignedCertificates(ctx context.Context) ([]*database.SignedCertificate, error) {
	res, err := c.client.Get(ctx, "ca/signed_cert/", clientv3.WithPrefix())
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	signedCertificates := make([]*database.SignedCertificate, 0, res.Count)
	for _, v := range res.Kvs {
		signedCertificate := &database.SignedCertificate{}
		if err := gob.NewDecoder(bytes.NewReader(v.Value)).Decode(signedCertificate); err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}
		signedCertificates = append(signedCertificates, signedCertificate)
	}

	return signedCertificates, nil
}

func (c *CA) GetSignedCertificate(ctx context.Context, serial *big.Int) (*database.SignedCertificate, error) {
	res, err := c.client.Get(ctx, fmt.Sprintf("ca/signed_cert/%x", serial))
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	if res.Count == 0 {
		return nil, xerrors.New("etcd: not found certificate")
	}

	signedCertificate := &database.SignedCertificate{}
	err = gob.NewDecoder(bytes.NewReader(res.Kvs[0].Value)).Decode(signedCertificate)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	return signedCertificate, nil
}

func (c *CA) GetRevokedCertificates(ctx context.Context) ([]*database.RevokedCertificate, error) {
	res, err := c.client.Get(ctx, "ca/revoke", clientv3.WithPrefix())
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	revoked := make([]*database.RevokedCertificate, 0, res.Count)
	for _, v := range res.Kvs {
		r := &database.RevokedCertificate{}
		err := gob.NewDecoder(bytes.NewReader(v.Value)).Decode(r)
		if err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}
		revoked = append(revoked, r)
	}

	return revoked, nil
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
	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(&database.RevokedCertificate{
		CommonName:   certificate.Certificate.Subject.CommonName,
		SerialNumber: certificate.Certificate.SerialNumber,
		IssuedAt:     certificate.IssuedAt,
		RevokedAt:    time.Now(),
		Comment:      certificate.Comment,
	})
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	key := fmt.Sprintf("ca/revoke/%x", certificate.Certificate.SerialNumber)
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

	_, err = c.client.Delete(ctx, fmt.Sprintf("ca/signed_cert/%x", certificate.Certificate.SerialNumber))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	return nil
}

func (c *CA) SetSignedCertificate(ctx context.Context, certificate *database.SignedCertificate) error {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(certificate); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	_, err := c.client.Put(ctx, fmt.Sprintf("ca/signed_cert/%x", certificate.Certificate.SerialNumber), buf.String())
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	return nil
}

func (c *CA) newSerialNumber(ctx context.Context) (*big.Int, error) {
	var serial *big.Int
	retry := 0
	for {
		if retry == 3 {
			return nil, xerrors.New("etcd: can not generate new serial number")
		}

		s, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
		if err != nil {
			return nil, xerrors.Errorf(": %v", err)
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
