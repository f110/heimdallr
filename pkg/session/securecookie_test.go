package session

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureCookieStore(t *testing.T) {
	s, err := NewSecureCookieStore([]byte("hashkeyhashkey"), []byte("blockkeyblockkey"), "example.com")
	require.NoError(t, err)

	sess := New("foobar")
	w := httptest.NewRecorder()
	err = s.SetSession(w, sess)
	require.NoError(t, err)
	c := w.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	req.AddCookie(c)
	gotSess, err := s.GetSession(req)
	require.NoError(t, err)

	assert.Equal(t, sess.Unique, gotSess.Unique)
	assert.Equal(t, sess.Id, gotSess.Id)

	buf := new(bytes.Buffer)
	require.NoError(t, gob.NewEncoder(buf).Encode(sess))
	offset := bytes.Index(buf.Bytes(), []byte("foobar"))
	require.NotEqual(t, -1, offset)

	parts := strings.SplitN(c.Value, ".", 2)
	ciphertext, err := base64.URLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	mac, err := base64.URLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	pos := s.cipherBlock.BlockSize() + offset + len("foobar") - 1
	ciphertext[pos] ^= 'r' ^ 'z'
	forgedMac := append(append([]byte{}, ciphertext...), mac[len(mac)-sha256.Size:]...)
	forged := base64.URLEncoding.EncodeToString(ciphertext) + "." + base64.URLEncoding.EncodeToString(forgedMac)

	_, err = s.DecodeValue(forged)
	assert.Error(t, err)
}
