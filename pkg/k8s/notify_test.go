package k8s

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func TestNewVolumeWatcher(t *testing.T) {
	fired := make(chan struct{})
	w, err := NewVolumeWatcher("/tmp", func() {
		fired <- struct{}{}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Stop()

	eventCh := make(chan fsnotify.Event)
	w.watcher.Events = eventCh
	eventCh <- fsnotify.Event{Op: fsnotify.Create, Name: "/tmp/..data"}

	select {
	case <-time.After(50 * time.Millisecond):
		t.Fatal("not fired")
	case <-fired:
	}
}

func TestCanWatchVolume(t *testing.T) {
	t.Run("Dir", func(t *testing.T) {
		d := t.TempDir()

		if err := os.Mkdir(filepath.Join(d, "data"), 0755); err != nil {
			t.Fatal(err)
		}
		if CanWatchVolume(d) {
			t.Fatal("CanWatchVolume should return false")
		}

		if err := os.Mkdir(filepath.Join(d, "..data"), 0755); err != nil {
			t.Fatal()
		}
		if CanWatchVolume(d) {
			t.Fatal("CanWatchVolume should return false")
		}

		if err := os.Remove(filepath.Join(d, "..data")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(d, "data"), filepath.Join(d, "..data")); err != nil {
			t.Fatal(err)
		}
		if !CanWatchVolume(d) {
			t.Fatal("CanWatchVolume should return true")
		}
	})

	t.Run("File", func(t *testing.T) {
		d := t.TempDir()

		if err := os.Mkdir(filepath.Join(d, "data"), 0755); err != nil {
			t.Fatal(err)
		}
		if CanWatchVolume(filepath.Join(d, "memo.txt")) {
			t.Fatal("CanWatchVolume should return false")
		}

		if err := os.Mkdir(filepath.Join(d, "..data"), 0755); err != nil {
			t.Fatal()
		}
		if CanWatchVolume(filepath.Join(d, "memo.txt")) {
			t.Fatal("CanWatchVolume should return false")
		}

		if err := os.Remove(filepath.Join(d, "..data")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(d, "data"), filepath.Join(d, "..data")); err != nil {
			t.Fatal(err)
		}
		if !CanWatchVolume(filepath.Join(d, "memo.txt")) {
			t.Fatal("CanWatchVolume should return true")
		}
	})
}

func TestFindMountPath(t *testing.T) {
	_, err := FindMountPath("hoge")
	if err == nil {
		t.Fatal("expected return error")
	}

	d := t.TempDir()

	_, err = FindMountPath(filepath.Join(d, "data/memo.txt"))
	if err == nil {
		t.Fatal("expected return error")
	}

	if err := os.Symlink(filepath.Join(d, "data"), filepath.Join(d, "..data")); err != nil {
		t.Fatal(err)
	}
	m, err := FindMountPath(filepath.Join(d, "data/memo.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if m != d {
		t.Fatalf("FindMountPath should return %s: %s", d, m)
	}
}
