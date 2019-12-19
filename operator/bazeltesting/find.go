package bazeltesting

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

func FindEtcd() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	e, err := findExternal(wd)
	if err != nil {
		return "", err
	}
	path := filepath.Join(e, "io_etcd/etcd")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", errors.New("bazeltesting: can't find etcd binary")
	}

	return path, nil
}

func FindKubeApiserver() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	e, err := findExternal(wd)
	if err != nil {
		return "", err
	}
	path := filepath.Join(e, "io_k8s_kube_apiserver/kube-apiserver")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", errors.New("bazeltesting: can't find kube-apiserver binary")
	}

	return path, err
}

func findExternal(start string) (string, error) {
	p := start
	for {
		files, err := ioutil.ReadDir(p)
		if err != nil {
			return "", err
		}
		for _, v := range files {
			if strings.HasSuffix(filepath.Join(p, v.Name()), "__main__/external") {
				return filepath.Join(p, v.Name()), nil
			}
		}
		p = filepath.Dir(p)
		if p == "/" {
			break
		}
	}

	return "", errors.New("bazeltesting: can't find external")
}
