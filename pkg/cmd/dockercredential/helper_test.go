package dockercredential

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.f110.dev/heimdallr/pkg/config/userconfig"
)

func newHelper(t *testing.T, stored *userconfig.Token) (*Helper, *[]string) {
	t.Setenv("HOME", t.TempDir())
	uc, err := userconfig.New()
	require.NoError(t, err)
	if stored != nil {
		require.NoError(t, uc.SetToken(stored.Endpoint, stored.Token, stored.ExpiresAt))
	}

	var requested []string
	h := &Helper{
		userDir: uc,
		requestToken: func(endpoint string) (string, time.Time, error) {
			requested = append(requested, endpoint)
			return "new-token", time.Now().Add(time.Hour), nil
		},
	}
	return h, &requested
}

func TestHelper_Run(t *testing.T) {
	t.Run("get", func(t *testing.T) {
		h, requested := newHelper(t, &userconfig.Token{Endpoint: "https://example.com/token", Token: "test-token", ExpiresAt: time.Now().Add(time.Hour)})

		out := new(bytes.Buffer)
		code := h.Run([]string{"get"}, strings.NewReader("registry.example.com\n"), out)
		require.Equal(t, 0, code, out.String())

		cred := &Credential{}
		require.NoError(t, json.Unmarshal(out.Bytes(), cred))
		assert.Equal(t, &Credential{ServerURL: "registry.example.com", Username: Username, Secret: "test-token"}, cred)
		assert.Empty(t, *requested)
	})

	t.Run("get with expired token", func(t *testing.T) {
		h, requested := newHelper(t, &userconfig.Token{Endpoint: "https://example.com/token", Token: "test-token", ExpiresAt: time.Now().Add(-time.Second)})

		out := new(bytes.Buffer)
		code := h.Run([]string{"get"}, strings.NewReader("registry.example.com"), out)
		require.Equal(t, 0, code, out.String())

		cred := &Credential{}
		require.NoError(t, json.Unmarshal(out.Bytes(), cred))
		assert.Equal(t, "new-token", cred.Secret)
		assert.Equal(t, []string{"https://example.com/token"}, *requested)

		stored, err := h.userDir.GetToken()
		require.NoError(t, err)
		assert.Equal(t, "new-token", stored.Token)
		assert.Equal(t, "https://example.com/token", stored.Endpoint)
		assert.False(t, stored.IsExpired())
	})

	t.Run("get without login", func(t *testing.T) {
		h, requested := newHelper(t, nil)

		out := new(bytes.Buffer)
		code := h.Run([]string{"get"}, strings.NewReader("registry.example.com"), out)
		assert.Equal(t, 1, code)
		assert.Equal(t, "credentials not found in native keychain\n", out.String())
		assert.Empty(t, *requested)
	})

	t.Run("get without server url", func(t *testing.T) {
		h, _ := newHelper(t, &userconfig.Token{Endpoint: "https://example.com/token", Token: "test-token", ExpiresAt: time.Now().Add(time.Hour)})

		out := new(bytes.Buffer)
		code := h.Run([]string{"get"}, strings.NewReader(""), out)
		assert.Equal(t, 1, code)
		assert.Equal(t, "no credentials server URL\n", out.String())
	})

	t.Run("store", func(t *testing.T) {
		stored := &userconfig.Token{Endpoint: "https://example.com/token", Token: "test-token", ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second)}
		h, _ := newHelper(t, stored)

		out := new(bytes.Buffer)
		code := h.Run([]string{"store"}, strings.NewReader(`{"ServerURL":"registry.example.com","Username":"foo","Secret":"bar"}`), out)
		assert.Equal(t, 0, code)
		assert.Empty(t, out.String())

		got, err := h.userDir.GetToken()
		require.NoError(t, err)
		assert.Equal(t, "test-token", got.Token)
	})

	t.Run("erase", func(t *testing.T) {
		h, _ := newHelper(t, &userconfig.Token{Endpoint: "https://example.com/token", Token: "test-token", ExpiresAt: time.Now().Add(time.Hour)})

		out := new(bytes.Buffer)
		code := h.Run([]string{"erase"}, strings.NewReader("registry.example.com"), out)
		assert.Equal(t, 0, code)
		assert.Empty(t, out.String())

		got, err := h.userDir.GetToken()
		require.NoError(t, err)
		assert.Equal(t, "test-token", got.Token)
	})

	t.Run("list", func(t *testing.T) {
		h, _ := newHelper(t, &userconfig.Token{Endpoint: "https://example.com/token", Token: "test-token", ExpiresAt: time.Now().Add(time.Hour)})

		out := new(bytes.Buffer)
		code := h.Run([]string{"list"}, strings.NewReader(""), out)
		assert.Equal(t, 0, code)
		assert.JSONEq(t, `{}`, out.String())
	})

	t.Run("unknown action", func(t *testing.T) {
		h, _ := newHelper(t, nil)

		out := new(bytes.Buffer)
		assert.Equal(t, 1, h.Run([]string{"unknown"}, strings.NewReader(""), out))
		assert.Equal(t, 1, h.Run(nil, strings.NewReader(""), out))
	})
}
