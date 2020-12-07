package template

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestNew(t *testing.T) {
	v := New(
		map[string]string{"/data/test": ""},
		LoaderTypeEmbed,
		"/data",
		map[string]interface{}{
			"test": func() bool { return true },
		},
	)
	if v == nil {
		t.Fatal("New should return a value")
	}
}

func TestLoader_Render(t *testing.T) {
	dir := t.TempDir()

	if err := os.MkdirAll(filepath.Join(dir, "data"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(filepath.Join(dir, "data", "test"), []byte("{{ .Test }}"), 0644); err != nil {
		t.Fatal(err)
	}

	v := New(
		nil,
		LoaderTypeShotgun,
		dir,
		map[string]interface{}{
			"test": func() bool { return true },
		},
	)

	buf := new(bytes.Buffer)
	if err := v.Render(buf, "data/test", struct {
		Test string
	}{
		Test: "This is test",
	}); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "This is test" {
		t.Errorf("Expect rendered result is \"This is test\": %s", buf.String())
	}
}
