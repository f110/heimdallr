package template

import (
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/logger"
)

const (
	LoaderTypeShotgun = "shotgun"
	LoaderTypeEmbed   = "embed"
)

type Loader struct {
	tmpl    *template.Template
	dir     string
	funcMap template.FuncMap
}

func New(data map[string]string, typ, dir string, funcMap template.FuncMap) *Loader {
	loader := &Loader{dir: dir, funcMap: funcMap}
	if typ == LoaderTypeEmbed {
		d := dir
		if !strings.HasSuffix(dir, "/") {
			d = dir + "/"
		}
		t := template.New("")
		if funcMap != nil {
			t = t.Funcs(funcMap)
		}
		for k, v := range data {
			name := strings.TrimPrefix(k, d)
			t = t.New(name)
			if _, err := t.Parse(v); err != nil {
				logger.Log.Info("Failure parse template", zap.Error(err))
			}
		}
		loader.tmpl = t
	}

	return loader
}

func (l *Loader) Render(w io.Writer, name string, data interface{}) error {
	var tmpl *template.Template
	if l.tmpl == nil {
		t := template.New("")
		if l.funcMap != nil {
			t = t.Funcs(l.funcMap)
		}
		parsed := make(map[string]struct{})
		_ = filepath.Walk(l.dir, func(path string, info os.FileInfo, err error) error {
			if os.IsNotExist(err) {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			if info.Name() == "BUILD.bazel" {
				return nil
			}

			name := strings.TrimPrefix(path, l.dir+"/")
			if _, ok := parsed[name]; ok {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return xerrors.Errorf(": %v", err)
			}

			t = t.New(name)
			_, err = t.Parse(string(b))
			if err != nil {
				logger.Log.Debug("Failure parsing template", zap.Error(err))
				return xerrors.Errorf(": %v", err)
			}
			parsed[name] = struct{}{}

			return nil
		})
		tmpl = t
	} else {
		tmpl = l.tmpl
	}

	return tmpl.ExecuteTemplate(w, name, data)
}
