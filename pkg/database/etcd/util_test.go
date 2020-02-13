package etcd

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/embed"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/netutil"
)

var (
	etcdUrl *url.URL
	client  *clientv3.Client
)

func clearDatabase(t *testing.T) {
	_, err := client.Delete(context.Background(), "", clientv3.WithPrefix())
	if err != nil {
		t.Fatal(err)
	}
}

func TestMain(m *testing.M) {
	dataDir, err := ioutil.TempDir("", "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create a temporary directory: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dataDir)

	port, err := netutil.FindUnusedPort()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not find an unused port: %v\n", err)
		os.Exit(1)
	}
	etcdUrl, err = url.Parse(fmt.Sprintf("http://localhost:%d", port))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed parse an url: %v", err)
		os.Exit(1)
	}

	c := embed.NewConfig()
	c.Dir = dataDir
	c.LogPkgLevels = "*=C"
	c.LPUrls[0].Host = "localhost:0"
	c.LCUrls[0] = *etcdUrl
	c.SetupLogging()

	e, err := embed.StartEtcd(c)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	select {
	case <-e.Server.ReadyNotify():
	case <-time.After(10 * time.Second):
		fmt.Fprintln(os.Stderr, "Failed start embed etcd")
		os.Exit(1)
	}

	client, err = clientv3.New(clientv3.Config{
		Endpoints:   []string{etcdUrl.String()},
		DialTimeout: 1 * time.Second,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed connect to etcd: %v\n", err)
		os.Exit(1)
	}

	logger.Init(&config.Logger{Level: "debug"})

	os.Exit(m.Run())
}
