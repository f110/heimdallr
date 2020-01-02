package localproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"

	"github.com/f110/lagrangian-proxy/pkg/auth/token"
	"github.com/keybase/go-keychain"
	"golang.org/x/xerrors"
)

const (
	keychainApplicationLabel = "lag-proxy"
)

var (
	ErrNotHaveCertificate = xerrors.New("localproxy: doesn't have certificate")
	ErrPrivateKeyNotFound = xerrors.New("localproxy: private key not found in keychain")
)

type Identity struct {
	Token       string
	Certificate *tls.Certificate
}

type IdentityProvider struct {
	tokenClient *token.TokenClient
}

func NewIdentityProvider(tokenFilename string) *IdentityProvider {
	return &IdentityProvider{tokenClient: token.NewTokenClient(tokenFilename)}
}

func (p *IdentityProvider) Provide() (*Identity, error) {
	privateKey, err := p.fetchPrivateKey()
	if err != nil && err != ErrPrivateKeyNotFound {
		return nil, err
	}
	if err == ErrPrivateKeyNotFound {
		key, err := p.generatePrivateKey()
		if err != nil {
			return nil, xerrors.Errorf(": %v", err)
		}
		privateKey = key
	}
	_ = privateKey

	t, err := p.tokenClient.GetToken()
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	return &Identity{Token: t}, nil
}

func (p *IdentityProvider) getCertificate() (*tls.Certificate, error) {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassCertificate)
	res, err := keychain.QueryItem(query)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	if len(res) == 0 {
		return nil, ErrNotHaveCertificate
	}
	certBlock := res[0].Data

	cert, err := tls.X509KeyPair(certBlock, nil)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	return &cert, nil
}

func (p *IdentityProvider) fetchPrivateKey() (*ecdsa.PrivateKey, error) {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassKey)
	item.SetKeyType(keychain.KeyTypeECDSA)
	item.SetKeySizeInBits(256)
	item.SetCanSign(true)
	item.SetApplicationLabel(keychainApplicationLabel)
	res, err := keychain.QueryItem(item)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	if len(res) == 0 {
		return nil, ErrPrivateKeyNotFound
	}

	return x509.ParseECPrivateKey(res[0].Data)
}

func (p *IdentityProvider) generatePrivateKey() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	item := keychain.NewItem()
	item.SetKeyType(keychain.KeyTypeEC)
	item.SetKeyClass(keychain.KeyClassPrivate)
	item.SetKeySizeInBits(256)
	item.SetCanSign(true)
	item.SetApplicationLabel(keychainApplicationLabel)
	item.SetData(keyBytes)
	if err := keychain.AddItem(item); err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	return privateKey, nil
}

func (p *IdentityProvider) storeCertificate(certificate x509.Certificate) {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassCertificate)
	item.SetData(certificate.Raw)
	keychain.AddItem(item)
}
