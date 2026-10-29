//go:build unix

package discover

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func TestNonRegularFilesRefused(t *testing.T) {
	root := fixtureDir(t)
	path := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal("create FIFO fixture")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0) //nolint:gosec // Private generated FIFO fixture.
	if err != nil {
		t.Fatal("open FIFO fixture")
	}
	defer func() { _ = f.Close() }()
	// Closing a connected writer produces EOF, so a missing type guard cannot
	// pass this test merely because a nonblocking read returns EAGAIN.
	writer, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0) //nolint:gosec // Private generated FIFO fixture.
	if err != nil {
		t.Fatal("connect FIFO fixture")
	}
	if err := writer.Close(); err != nil {
		t.Fatal("close FIFO writer")
	}
	t.Run("fifo", func(t *testing.T) {
		if b, err := readBounded(f, 1024); !errors.Is(err, ErrRead) || len(b) != 0 {
			t.Fatal("FIFO admitted")
		}
	})
	t.Run("device", func(t *testing.T) {
		device, err := os.Open("/dev/null")
		if err != nil {
			t.Fatal("open character device fixture")
		}
		defer func() { _ = device.Close() }()
		info, err := device.Stat()
		if err != nil || info.Mode()&os.ModeCharDevice == 0 {
			t.Fatal("character device control unavailable")
		}
		if b, err := readBounded(device, 1024); !errors.Is(err, ErrRead) || len(b) != 0 {
			t.Fatal("character device admitted")
		}
	})
	put(t, root, "regular", "synthetic")
	regular, err := os.Open(filepath.Join(root, "regular")) //nolint:gosec // Private generated regular fixture.
	if err != nil {
		t.Fatal("open regular control")
	}
	defer func() { _ = regular.Close() }()
	b, err := readBounded(regular, 1024)
	defer wipe(b)
	if err != nil || len(b) != len("synthetic") {
		t.Fatal("regular file control refused")
	}
}
