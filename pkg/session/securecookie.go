package session

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.f110.dev/xerrors"
)

type SecureCookieStore struct {
	Domain string

	hashKey     []byte
	cipherKey   []byte
	cipherBlock cipher.Block
	bufPool     sync.Pool
}

func NewSecureCookieStore(hashKey, blockKey []byte, domain string) (*SecureCookieStore, error) {
	cipherBlock, err := aes.NewCipher(blockKey)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	return &SecureCookieStore{
		Domain:      domain,
		hashKey:     hashKey,
		cipherBlock: cipherBlock,
		bufPool: sync.Pool{
			New: func() any { return new(bytes.Buffer) },
		},
	}, nil
}

func (s *SecureCookieStore) GetSession(req *http.Request) (*Session, error) {
	c, err := req.Cookie(CookieName)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	sess, err := s.DecodeValue(c.Value)
	if err != nil {
		return nil, err
	}

	if sess.IssuedAt.Add(Expiration).Before(time.Now()) {
		return nil, ErrSessionExpired
	}
	return sess, nil
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
	// Serialize the Session
	buf := s.bufPool.Get().(*bytes.Buffer)
	defer s.bufPool.Put(buf)
	buf.Reset()
	if err := gob.NewEncoder(buf).Encode(sess); err != nil {
		return nil, xerrors.WithStack(err)
	}
	plain := buf.Bytes()

	// Encrypt
	ciphertext := make([]byte, s.cipherBlock.BlockSize()+buf.Len())
	iv := ciphertext[:s.cipherBlock.BlockSize()]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, xerrors.WithMessage(err, "failed to generate initial vector")
	}
	stream := cipher.NewCTR(s.cipherBlock, iv)
	stream.XORKeyStream(ciphertext[s.cipherBlock.BlockSize():], plain)

	// Calculate HMAC
	h := hmac.New(sha256.New, s.hashKey)
	mac := h.Sum(ciphertext)

	// Encode segment
	value := fmt.Sprintf("%s.%s", base64.URLEncoding.EncodeToString(ciphertext), base64.URLEncoding.EncodeToString(mac))

	return &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		Domain:   s.Domain,
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
		Secure:   true,
	}, nil
}

func (s *SecureCookieStore) DecodeValue(value string) (*Session, error) {
	i := strings.IndexRune(value, '.')
	if i == -1 {
		return nil, xerrors.NewWithStack("invalid session value")
	}
	cipherValue, err := base64.URLEncoding.DecodeString(value[:i])
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	mac, err := base64.URLEncoding.DecodeString(value[i+1:])
	if err != nil {
		return nil, xerrors.WithStack(err)
	}
	calculatedMac := hmac.New(sha256.New, s.hashKey).Sum(cipherValue)
	if !hmac.Equal(calculatedMac, mac) {
		return nil, xerrors.NewWithStack("invalid session value")
	}
	iv := cipherValue[:s.cipherBlock.BlockSize()]
	stream := cipher.NewCTR(s.cipherBlock, iv)
	plain := make([]byte, len(value)-s.cipherBlock.BlockSize())
	stream.XORKeyStream(plain, cipherValue[s.cipherBlock.BlockSize():])

	sess := &Session{}
	if err := gob.NewDecoder(bytes.NewReader(plain)).Decode(sess); err != nil {
		return nil, xerrors.WithStack(err)
	}
	return sess, nil
}

func GenerateRandomKey(size int) []byte {
	buf := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil
	}
	return buf
}
