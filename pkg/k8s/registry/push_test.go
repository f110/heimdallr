package registry

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImageFromLayout(t *testing.T) {
	amd64 := v1.Platform{OS: "linux", Architecture: "amd64"}
	arm64 := v1.Platform{OS: "linux", Architecture: "arm64"}

	newImage := func(t *testing.T) v1.Image {
		img, err := random.Image(128, 1)
		require.NoError(t, err)
		return img
	}
	writeLayout := func(t *testing.T, idx v1.ImageIndex) string {
		dir := t.TempDir()
		_, err := layout.Write(dir, idx)
		require.NoError(t, err)
		return dir
	}
	digest := func(t *testing.T, img v1.Image) v1.Hash {
		h, err := img.Digest()
		require.NoError(t, err)
		return h
	}

	t.Run("NestedIndex", func(t *testing.T) {
		amd64Image, arm64Image := newImage(t), newImage(t)
		inner := mutate.AppendManifests(empty.Index,
			mutate.IndexAddendum{Add: amd64Image, Platform: &amd64},
			mutate.IndexAddendum{Add: arm64Image, Platform: &arm64},
		)
		dir := writeLayout(t, mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: inner}))

		got, err := ImageFromLayout(dir, arm64)
		require.NoError(t, err)
		assert.Equal(t, digest(t, arm64Image), digest(t, got))
	})

	t.Run("Index", func(t *testing.T) {
		amd64Image, arm64Image := newImage(t), newImage(t)
		dir := writeLayout(t, mutate.AppendManifests(empty.Index,
			mutate.IndexAddendum{Add: amd64Image, Platform: &amd64},
			mutate.IndexAddendum{Add: arm64Image, Platform: &arm64},
		))

		got, err := ImageFromLayout(dir, amd64)
		require.NoError(t, err)
		assert.Equal(t, digest(t, amd64Image), digest(t, got))
	})

	t.Run("SingleImage", func(t *testing.T) {
		image := newImage(t)
		dir := writeLayout(t, mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: image}))

		got, err := ImageFromLayout(dir, arm64)
		require.NoError(t, err)
		assert.Equal(t, digest(t, image), digest(t, got))
	})

	t.Run("NotFound", func(t *testing.T) {
		dir := writeLayout(t, mutate.AppendManifests(empty.Index,
			mutate.IndexAddendum{Add: newImage(t), Platform: &amd64},
		))

		_, err := ImageFromLayout(dir, arm64)
		assert.ErrorIs(t, err, ErrImageNotFound)
	})
}
