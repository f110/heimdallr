package config

import (
	"io/ioutil"
	"path/filepath"
	"testing"
)

func TestReadConfig(t *testing.T) {
	b := `
datastore:
  url: etcd://embed
  data_dir: ./data
logger:
  level: debug
  encoding: console
`

	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal(err)
	}
	f, err := ioutil.TempFile(tmpDir, "")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(b)
	f.Sync()
	f.Seek(0, 0)

	conf, err := ReadConfig(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if conf.Datastore == nil {
		t.Fatal("yaml parse error or something")
	}
	if conf.Datastore.Url.Scheme != "etcd" {
		t.Errorf("datastore url is expected etcd: %s", conf.Datastore.Url.Scheme)
	}
	if conf.Datastore.Url.Hostname() != "embed" {
		t.Errorf("datastore host is expect embed: %s", conf.Datastore.Url.Hostname())
	}
	if conf.Logger == nil {
		t.Fatal("yaml parse error or something")
	}
	if conf.Logger.Level != "debug" {
		t.Errorf("expect logger level is debug: %s", conf.Logger.Level)
	}
	if conf.Logger.Encoding != "console" {
		t.Errorf("expect logger encoding is console: %s", conf.Logger.Encoding)
	}
	if conf.Datastore.DataDir != filepath.Join(tmpDir, "data") {
		t.Errorf("datastore.data expect %s: %s", filepath.Join(tmpDir, "data"), conf.Datastore.DataDir)
	}

	err = ioutil.WriteFile(filepath.Join(tmpDir, "data", embedEtcdUrlFilename), []byte("etcd://localhost:60000"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	conf, err = ReadConfig(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if conf.Datastore.EtcdUrl.Host != "localhost:60000" {
		t.Errorf("failed read previous etcd url: %s", conf.Datastore.EtcdUrl.String())
	}
}
