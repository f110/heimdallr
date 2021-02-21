package k8s

import (
	"os"
	"testing"
)

func TestGetClusterDomain(t *testing.T) {
	f, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	oldValue := ResolvFile
	ResolvFile = f.Name()
	defer func() {
		ResolvFile = oldValue
	}()

	f.WriteString("nameserver 127.0.0.1\n")
	f.WriteString("search svc.cluster.local cluster.local")
	f.Close()

	domain, err := GetClusterDomain()
	if err != nil {
		t.Fatal(err)
	}
	if domain != "cluster.local" {
		t.Errorf("cluster domain is cluster.local: %s", domain)
	}
}
