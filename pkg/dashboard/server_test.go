package dashboard

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.f110.dev/heimdallr/pkg/config/configv2"
)

func newSPAServer(t *testing.T) *Server {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "assets"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "assets", "index.js"), []byte("console.log(1)"), 0644))

	return &Server{Config: &configv2.Config{Dashboard: &configv2.Dashboard{AssetDir: dir}}}
}

func TestSPAHandler(t *testing.T) {
	handler := newSPAServer(t).spaHandler()

	cases := []struct {
		path string
		body string
	}{
		{path: "/", body: "<!doctype html>"},
		{path: "/assets/index.js", body: "console.log(1)"},
		// The client side routing owns every unknown path.
		{path: "/user/foo@example.com", body: "<!doctype html>"},
		{path: "/assets", body: "<!doctype html>"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, tc.body, w.Body.String())
		})
	}
}

func TestSPAHandlerDoesNotEscapeTheAssetDir(t *testing.T) {
	handler := newSPAServer(t).spaHandler()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.URL.Path = "/../../etc/passwd"
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NotContains(t, w.Body.String(), "root:")
}
