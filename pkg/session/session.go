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

type Session struct {
	Id string
}

type SecureCookie struct {
	Id string
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

	co := &SecureCookie{}
	if err := s.s.Decode(c.Name, c.Value, co); err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	return &Session{Id: co.Id}, nil
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
		Domain:   "",
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
		Secure:   true,
	}, nil
}
