package token

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	NewClient(net.DefaultResolver)
}

func TestClient_RequestToken(t *testing.T) {
	forTestMock = true
	tmpHome := t.TempDir()
	os.Setenv("HOME", tmpHome)

	u, err := url.Parse(ClientRedirectUrl)
	require.NoError(t, err)
	go func() {
		for {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf(":%s", u.Port()), 10*time.Millisecond)
			if err != nil {
				continue
			}
			conn.Close()
			break
		}

		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://localhost:%s?code=%s", u.Port(), "test-code"), nil)
		require.NoError(t, err)
		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		require.NoError(t, res.Body.Close())
	}()

	gotCode := ""
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		v := req.URL.Query()
		gotCode = v.Get("code")

		token := &ExchangeResponse{
			AccessToken: t.Name(),
		}
		require.NoError(t, json.NewEncoder(w).Encode(token))
	}))

	c := NewClient(net.DefaultResolver)
	gotToken, err := c.RequestToken(s.URL, "")
	require.NoError(t, err)

	assert.Equal(t, t.Name(), gotToken)
	assert.Equal(t, "test-code", gotCode)
}
