package template

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.f110.dev/heimdallr/pkg/config/configv2"
	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/tmpl/dashboard"
)

func TestMain(m *testing.M) {
	logger.Init(&configv2.Logger{Level: "debug"})

	m.Run()
}

func TestNew(t *testing.T) {
	v := New(
		dashboard.Data,
		LoaderTypeEmbed,
		"/data",
		map[string]interface{}{
			"test": func() bool { return true },
		},
	)
	assert.NotNil(t, v)
}

func TestLoader_Render(t *testing.T) {
	dir := t.TempDir()

	err := os.MkdirAll(filepath.Join(dir, "data"), 0755)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dir, "data", "test"), []byte("{{ .Test }}"), 0644)
	require.NoError(t, err)

	v := New(
		dashboard.Data,
		LoaderTypeShotgun,
		dir,
		map[string]interface{}{
			"test": func() bool { return true },
		},
	)

	buf := new(bytes.Buffer)
	err = v.Render(buf, "data/test", struct {
		Test string
	}{
		Test: "This is test",
	})
	require.NoError(t, err)
	assert.Equal(t, "This is test", buf.String())
}
