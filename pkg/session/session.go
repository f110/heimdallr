package session

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"time"

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
	Unique          string // Unique is a random value
	Id              string // Id is an identifier of user
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
