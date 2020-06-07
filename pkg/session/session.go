package session

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"golang.org/x/xerrors"
)

const (
	CookieName = "heimdallr"
)

var (
	Expiration        = 24 * time.Hour
	ErrSessionExpired = xerrors.New("session: expired")
)

type Session struct {
	Unique          string
	Id              string
	IssuedAt        time.Time
	Challenge       string
	ChallengeMethod string
	From            string
}

func (s *Session) SetId(id string) {
	s.Id = id
	s.From = ""
	s.IssuedAt = time.Now()
}

func New(id string) *Session {
	buf := make([]byte, 10)
	_, _ = io.ReadFull(rand.Reader, buf)

	return &Session{Unique: base64.StdEncoding.EncodeToString(buf), Id: id, IssuedAt: time.Now()}
}

type Store interface {
	GetSession(req *http.Request) (*Session, error)
	SetSession(w http.ResponseWriter, sess *Session) error
}

type SecureCookieStore struct {
	Domain string
	s      *securecookie.SecureCookie
}

func NewSecureCookieStore(hasKey, blockKey []byte, domain string) *SecureCookieStore {
	return &SecureCookieStore{s: securecookie.New(hasKey, blockKey), Domain: domain}
}

func (s *SecureCookieStore) GetSession(req *http.Request) (*Session, error) {
	c, err := req.Cookie(CookieName)
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
	v, err := s.s.Encode(CookieName, sess)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	return &http.Cookie{
		Name:     CookieName,
		Value:    v,
		Path:     "/",
		Domain:   s.Domain,
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
		Secure:   true,
	}, nil
}
