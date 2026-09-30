package release

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContainerReleaseCmd(t *testing.T) {
	s := httptest.NewServer(registry.New())
	t.Cleanup(s.Close)
	u, err := url.Parse(s.URL)
	require.NoError(t, err)
	repository := fmt.Sprintf("%s/heimdallr/operator", u.Host)

	var addenda []mutate.IndexAddendum
	for _, arch := range []string{"amd64", "arm64"} {
		img, err := random.Image(1024, 1)
		require.NoError(t, err)
		img = mutate.MediaType(img, types.OCIManifestSchema1)
		addenda = append(addenda, mutate.IndexAddendum{
			Add:        img,
			Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}},
		})
	}
	idx := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, addenda...), types.OCIImageIndex)
	latest, err := name.NewTag(repository + ":latest")
	require.NoError(t, err)
	require.NoError(t, remote.WriteIndex(latest, idx))
	digest, err := idx.Digest()
	require.NoError(t, err)

	sha256File := filepath.Join(t.TempDir(), "digest")
	require.NoError(t, os.WriteFile(sha256File, []byte(digest.String()+"\n"), 0644))

	err = containerReleaseCmd(repository, sha256File, "v1.0.0", false)
	require.NoError(t, err)

	tag, err := name.NewTag(repository + ":v1.0.0")
	require.NoError(t, err)
	desc, err := remote.Get(tag)
	require.NoError(t, err)
	assert.Equal(t, types.OCIImageIndex, desc.MediaType)
	assert.Equal(t, digest, desc.Digest)
}
