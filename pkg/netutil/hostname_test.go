package netutil

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.f110.dev/heimdallr/pkg/k8s"
)

func TestGetHostname(t *testing.T) {
	t.Run("on-perm", func(t *testing.T) {
		got, err := GetHostname()
		require.NoError(t, err)

		hostname, err := os.Hostname()
		require.NoError(t, err)

		assert.Equal(t, hostname, got)
	})

	t.Run("on-k8s", func(t *testing.T) {
		tempFile, err := os.CreateTemp("", "k8s")
		require.NoError(t, err)
		defer os.Remove(tempFile.Name())
		tempFile.WriteString(`nameserver 10.96.0.10
search default.svc.cluster.example.com svc.cluster.example.com cluster.example.com
options ndots:5`)
		tempFile.Sync()
		tempFile.Close()

		orig := k8s.ResolvFile
		defer func() {
			k8s.ResolvFile = orig
		}()
		k8s.ResolvFile = tempFile.Name()
		os.Setenv(IPAddressEnvKey, "192.168.230.1")
		os.Setenv(NamespaceEnvKey, "proxy")
		defer func() {
			os.Unsetenv(IPAddressEnvKey)
			os.Unsetenv(NamespaceEnvKey)
		}()

		got, err := GetHostname()
		require.NoError(t, err)
		assert.Equal(t, "192-168-230-1.proxy.pod.cluster.example.com", got)
	})
}
