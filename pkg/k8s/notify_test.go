package k8s

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVolumeWatcher(t *testing.T) {
	fired := make(chan struct{})
	dir := t.TempDir()
	w, err := NewVolumeWatcher(dir, func() {
		fired <- struct{}{}
	})
	require.NoError(t, err)
	defer w.Stop()

	eventCh := make(chan fsnotify.Event)
	w.watcher.Events = eventCh
	eventCh <- fsnotify.Event{Op: fsnotify.Create, Name: filepath.Join(dir, "..data")}

	select {
	case <-time.After(50 * time.Millisecond):
		assert.Fail(t, "not fired")
	case <-fired:
	}
}

func TestCanWatchVolume(t *testing.T) {
	t.Run("Dir", func(t *testing.T) {
		d := t.TempDir()

		err := os.Mkdir(filepath.Join(d, "data"), 0755)
		require.NoError(t, err)
		require.False(t, CanWatchVolume(d))

		err = os.Mkdir(filepath.Join(d, "..data"), 0755)
		require.NoError(t, err)
		require.False(t, CanWatchVolume(d))

		err = os.Remove(filepath.Join(d, "..data"))
		require.NoError(t, err)
		err = os.Symlink(filepath.Join(d, "data"), filepath.Join(d, "..data"))
		require.NoError(t, err)
		require.True(t, CanWatchVolume(d))
	})

	t.Run("File", func(t *testing.T) {
		d := t.TempDir()

		err := os.Mkdir(filepath.Join(d, "data"), 0755)
		require.NoError(t, err)
		require.False(t, CanWatchVolume(filepath.Join(d, "memo.txt")))

		err = os.Mkdir(filepath.Join(d, "..data"), 0755)
		require.NoError(t, err)
		require.False(t, CanWatchVolume(filepath.Join(d, "memo.txt")))

		err = os.Remove(filepath.Join(d, "..data"))
		require.NoError(t, err)
		err = os.Symlink(filepath.Join(d, "data"), filepath.Join(d, "..data"))
		require.NoError(t, err)
		require.True(t, CanWatchVolume(filepath.Join(d, "memo.txt")))
	})
}

func TestFindMountPath(t *testing.T) {
	_, err := FindMountPath("hoge")
	require.Error(t, err)

	d := t.TempDir()

	_, err = FindMountPath(filepath.Join(d, "data/memo.txt"))
	require.Error(t, err)

	err = os.Symlink(filepath.Join(d, "data"), filepath.Join(d, "..data"))
	require.NoError(t, err)
	m, err := FindMountPath(filepath.Join(d, "data/memo.txt"))
	require.NoError(t, err)
	assert.Equal(t, d, m)
}
