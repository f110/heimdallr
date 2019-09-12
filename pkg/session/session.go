package session

import (
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"golang.org/x/xerrors"
)

const (
	cookieName = "lagrangian"
)

var (
	Expiration        = 24 * time.Hour
	ErrSessionExpired = xerrors.New("session: expired")
)

type Session struct {
	Id       string
	IssuedAt time.Time
}

func New(id string) *Session {
	return &Session{Id: id, IssuedAt: time.Now()}
}

type Store interface {
	GetSession(req *http.Request) (*Session, error)
	SetSession(w http.ResponseWriter, sess *Session) error
}

type SecureCookieStore struct {
	s *securecookie.SecureCookie
}

func NewSecureCookieStore(hasKey, blockKey []byte) *SecureCookieStore {
	return &SecureCookieStore{s: securecookie.New(hasKey, blockKey)}
}

func (s *SecureCookieStore) GetSession(req *http.Request) (*Session, error) {
	c, err := req.Cookie(cookieName)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	co := &Session{}
	if err := s.s.Decode(c.Name, c.Value, co); err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}
	if co.IssuedAt.Add(Expiration).Before(time.Now()) {
		return nil, ErrSessionExpired
	}

	return co, nil
}

func (s *SecureCookieStore) SetSession(w http.ResponseWriter, sess *Session) error {
	v, err := s.Cookie(sess)
	if err != nil {
		return err
	}

	http.SetCookie(w, v)
	return nil
}

func (s *SecureCookieStore) Cookie(sess *Session) (*http.Cookie, error) {
	v, err := s.s.Encode(cookieName, sess)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	return &http.Cookie{
		Name:     cookieName,
		Value:    v,
		Path:     "/",
		Domain:   "local-proxy.f110.dev",
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
		Secure:   true,
	}, nil
}
