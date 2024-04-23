package template

import (
	"embed"
	"html/template"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"go.f110.dev/xerrors"
	"go.uber.org/zap"

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

func New(data embed.FS, typ, dir string, funcMap template.FuncMap) *Loader {
	loader := &Loader{dir: dir, funcMap: funcMap}
	if typ == LoaderTypeEmbed {
		t := template.New("")
		if funcMap != nil {
			t = t.Funcs(funcMap)
		}

		err := fs.WalkDir(data, ".", func(path string, entry fs.DirEntry, err error) error {
			if entry.IsDir() {
				return nil
			}

			t = t.New(path)
			buf, err := data.ReadFile(path)
			if err != nil {
				return err
			}
			if _, err := t.Parse(string(buf)); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			logger.Log.Info("Failed walk embed files", zap.Error(err))
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
				return xerrors.WithStack(err)
			}

			t = t.New(name)
			_, err = t.Parse(string(b))
			if err != nil {
				logger.Log.Debug("Failure parsing template", zap.Error(err))
				return xerrors.WithStack(err)
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
