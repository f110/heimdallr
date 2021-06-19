package session

import (
	"bytes"
	"encoding/gob"
	"net/http"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/config/configv2"
)

type MemcachedStore struct {
	Domain string
	client *memcache.Client
}

var _ Store = &MemcachedStore{}

func NewMemcachedStore(conf *configv2.Session, domain string) *MemcachedStore {
	return &MemcachedStore{Domain: domain, client: memcache.New(conf.Servers...)}
}

func (m *MemcachedStore) GetSession(req *http.Request) (*Session, error) {
	c, err := req.Cookie(CookieName)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	return m.getFromMemcached(c.Value)
}

func (m *MemcachedStore) SetSession(w http.ResponseWriter, sess *Session) error {
	err := m.save(sess)
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	c := &http.Cookie{
		Name:     CookieName,
		Value:    sess.Unique,
		Path:     "/",
		Domain:   m.Domain,
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
		Secure:   true,
	}

	http.SetCookie(w, c)
	return nil
}

func (m *MemcachedStore) getFromMemcached(unique string) (*Session, error) {
	item, err := m.client.Get(unique)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	sess := &Session{}
	if err := gob.NewDecoder(bytes.NewReader(item.Value)).Decode(sess); err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	return sess, nil
}

func (m *MemcachedStore) save(sess *Session) error {
	value := new(bytes.Buffer)
	if err := gob.NewEncoder(value).Encode(sess); err != nil {
		return xerrors.Errorf(": %v", err)
	}

	err := m.client.Set(&memcache.Item{
		Key:        sess.Unique,
		Value:      value.Bytes(),
		Expiration: int32((24 * time.Hour).Seconds()),
	})
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	return nil
}
