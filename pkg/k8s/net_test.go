package k8s

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetClusterDomain(t *testing.T) {
	f, err := os.CreateTemp("", "")
	require.NoError(t, err)
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
	require.NoError(t, err)
	assert.Equal(t, "cluster.local", domain)
}
