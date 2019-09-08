package config

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/clientv3/namespace"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"
)

const (
	embedEtcdUrlFilename = "embed_etcd_url"
)

type Config struct {
	Datastore *Datastore `yaml:"datastore"`
	Logger    *Logger    `yaml:"logger"`
}

type Datastore struct {
	RawUrl    string `yaml:"url"`
	DataDir   string `yaml:"data_dir"`  // use only embed etcd
	Namespace string `yaml:"namespace"` // use only etcd

	Url        *url.URL         `yaml:"-"`
	Embed      bool             `yaml:"-"`
	EtcdUrl    *url.URL         `yaml:"-"`
	etcdClient *clientv3.Client `yaml:"-"`
}

type Logger struct {
	Level    string `yaml:"level"`
	Encoding string `yaml:"encoding"` // json or console
}

func ReadConfig(filename string) (*Config, error) {
	a, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(a)

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	conf := &Config{}
	if err := yaml.NewDecoder(f).Decode(conf); err != nil {
		return nil, xerrors.Errorf("config: file parse error: %v", err)
	}
	if conf.Datastore != nil {
		if err := conf.Datastore.inflate(dir); err != nil {
			return nil, err
		}
	}

	return conf, nil
}

func (d *Datastore) inflate(dir string) error {
	if d.RawUrl != "" {
		u, err := url.Parse(d.RawUrl)
		if err != nil {
			return err
		}
		d.Url = u

		if u.Host == "embed" {
			d.Embed = true
		}
	}
	if d.DataDir != "" {
		d.DataDir = absPath(d.DataDir, dir)
	}
	if d.Namespace != "" {
		if !strings.HasSuffix(d.Namespace, "/") {
			d.Namespace += "/"
		}
	} else {
		d.Namespace = "/"
	}

	switch d.Url.Scheme {
	case "etcd":
		if d.Embed {
			if _, err := os.Stat(filepath.Join(d.DataDir, embedEtcdUrlFilename)); os.IsNotExist(err) {
				// first time
				l, err := net.Listen("tcp", ":0")
				if err != nil {
					return xerrors.Errorf(": %v", err)
				}
				addr := l.Addr().(*net.TCPAddr)
				if err := l.Close(); err != nil {
					return xerrors.Errorf(": %v", err)
				}

				u := &url.URL{Scheme: "http", Host: fmt.Sprintf("localhost:%d", addr.Port)}
				if err := os.MkdirAll(filepath.Join(d.DataDir), 0755); err != nil {
					return xerrors.Errorf(": %v", err)
				}
				err = ioutil.WriteFile(filepath.Join(d.DataDir, embedEtcdUrlFilename), []byte(u.String()), 0600)
				if err != nil {
					return xerrors.Errorf(": %v", err)
				}
				d.EtcdUrl = u
			} else {
				b, err := ioutil.ReadFile(filepath.Join(d.DataDir, embedEtcdUrlFilename))
				if err != nil {
					return xerrors.Errorf(": %v", err)
				}
				u, err := url.Parse(string(b))
				if err != nil {
					return xerrors.Errorf(": %v", err)
				}
				d.EtcdUrl = u
			}
		} else {
			u := new(url.URL)
			*u = *d.Url
			u.Scheme = "http"
			d.EtcdUrl = u
		}
	}

	return nil
}

func (d *Datastore) GetEtcdClient() (*clientv3.Client, error) {
	if d.etcdClient != nil {
		return d.etcdClient, nil
	}

	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{d.EtcdUrl.String()},
		DialTimeout: 1 * time.Second,
	})
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	client.KV = namespace.NewKV(client.KV, d.Namespace)
	client.Lease = namespace.NewLease(client.Lease, d.Namespace)
	client.Watcher = namespace.NewWatcher(client.Watcher, d.Namespace)
	d.etcdClient = client
	return client, nil
}

func absPath(path, dir string) string {
	if strings.HasPrefix(path, "./") {
		a, err := filepath.Abs(filepath.Join(dir, path))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return ""
		}
		return a
	}
	return path
}
