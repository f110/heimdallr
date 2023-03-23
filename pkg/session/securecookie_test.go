package session

import (
	"net/http"
	"net/http/httptest"
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

	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	req.AddCookie(w.Result().Cookies()[0])
	gotSess, err := s.GetSession(req)
	require.NoError(t, err)

	assert.Equal(t, sess.Unique, gotSess.Unique)
	assert.Equal(t, sess.Id, gotSess.Id)
}
