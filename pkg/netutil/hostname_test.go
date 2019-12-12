package netutil

import (
	"io/ioutil"
	"os"
	"testing"
)

func TestGetHostname(t *testing.T) {
	t.Run("on-perm", func(t *testing.T) {
		got, err := GetHostname()
		if err != nil {
			t.Fatal(err)
		}

		hostname, err := os.Hostname()
		if err != nil {
			t.Fatal(err)
		}

		if got != hostname {
			t.Errorf("expect hostname is %s: %s", hostname, got)
		}
	})

	t.Run("on-k8s", func(t *testing.T) {
		tempFile, err := ioutil.TempFile("", "k8s")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tempFile.Name())
		tempFile.WriteString(`nameserver 10.96.0.10
search default.svc.cluster.example.com svc.cluster.example.com cluster.example.com
options ndots:5`)
		tempFile.Sync()
		tempFile.Close()

		orig := resolvFile
		defer func() {
			resolvFile = orig
		}()
		resolvFile = tempFile.Name()
		os.Setenv(IPAddressEnvKey, "192.168.230.1")
		os.Setenv(NamespaceEnvKey, "proxy")
		defer func() {
			os.Unsetenv(IPAddressEnvKey)
			os.Unsetenv(NamespaceEnvKey)
		}()

		got, err := GetHostname()
		if err != nil {
			t.Fatal(err)
		}
		if got != "192-168-230-1.proxy.pod.cluster.example.com" {
			t.Errorf("expected hostname is 192-168-230-1.proxy.pod.cluster.example.com: %s", got)
		}
	})
}
