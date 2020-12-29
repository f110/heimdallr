package userconfig

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
)

const (
	Directory     = ".heimdallr"
	tokenFilename = "token"
)

type UserDir struct {
	home string
}

func New() (*UserDir, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, xerrors.Errorf(": %w", err)
	}

	return &UserDir{home: home}, nil
}

func (u *UserDir) GetToken() (string, error) {
	b, err := u.readFile(tokenFilename)
	if err != nil {
		return "", xerrors.Errorf(": %w", err)
	}

	return string(b), nil
}

func (u *UserDir) SetToken(token string) error {
	if err := u.writeFile(tokenFilename, []byte(token)); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}

func (u *UserDir) readFile(filename string) ([]byte, error) {
	f, err := os.Open(filepath.Join(u.home, Directory, filename))
	if os.IsNotExist(err) {
		return nil, nil
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	return b, nil
}

func (u *UserDir) writeFile(filename string, content []byte) error {
	_, err := os.Stat(filepath.Join(u.home, Directory))
	if os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Join(u.home, Directory), 0755); err != nil {
			return xerrors.Errorf(": %v", err)
		}
	}
	f, err := os.Create(filepath.Join(u.home, Directory, filename))
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	_, err = f.Write(content)
	if err != nil {
		return xerrors.Errorf(": %w", err)
	}
	if err := f.Close(); err != nil {
		return xerrors.Errorf(": %w", err)
	}

	return nil
}
