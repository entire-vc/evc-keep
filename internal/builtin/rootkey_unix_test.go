//go:build unix

package builtin

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRootFileSizeLimit(t *testing.T) {
	root := bytes.Repeat([]byte{'*'}, 32)
	defer clear(root)
	encoded := []byte(base64.StdEncoding.EncodeToString(root))
	defer clear(encoded)
	for _, size := range []int{4096, 4097, 8192} {
		content := append(bytes.Clone(encoded), bytes.Repeat([]byte{' '}, size-len(encoded))...)
		path := filepath.Join(t.TempDir(), "root.key")
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal("write fixture")
		}
		clear(content)
		local, err := OpenLocalFile(nil, path, "test-root", nil, nopAudit)
		if size == 4096 {
			if err != nil || local == nil {
				t.Fatal("root size boundary control rejected")
			}
		} else if err == nil || local != nil {
			t.Fatal("oversized root file accepted")
		}
	}
}

func TestRootReadFailureWipesPartial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.key")
	partial := bytes.Repeat([]byte{'*'}, 32)
	if err := os.WriteFile(path, partial, 0600); err != nil {
		t.Fatal("write fixture")
	}
	called := false
	got, err := readLocalRootWith(path, func(r io.Reader) ([]byte, error) {
		called = true
		if b, e := io.ReadAll(r); e != nil || !bytes.Equal(b, partial) {
			t.Fatal("reader control failed")
		}
		return partial, errors.New("read failure " + string(partial[:12]))
	})
	if !called || err == nil || got != nil {
		t.Error("partial read was not refused")
	}
	if err != nil && bytes.Contains([]byte(err.Error()), bytes.Repeat([]byte{'*'}, 12)) {
		t.Error("partial root prefix leaked through error")
	}
	if !bytes.Equal(partial, make([]byte, len(partial))) {
		t.Error("partial root buffer was not wiped")
	}
}

func TestReadRootKeyFileAcceptsMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.key")
	if err := os.WriteFile(path, []byte("cGxhaW50ZXh0"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	got, err := readLocalRoot(path)
	defer clear(got)
	if err != nil {
		t.Fatalf("readLocalRoot: %v", err)
	}
	if string(got) != "cGxhaW50ZXh0" {
		t.Fatal("readLocalRoot did not return fixture contents")
	}
}

// TestReadRootKeyFileRefusesWideMode is the guard's own red run: without the
// mode check, a root key file readable by other local users would load
// silently. Widen the fixture's mode and require rejection.
func TestReadRootKeyFileRefusesWideMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.key")
	if err := os.WriteFile(path, []byte("cGxhaW50ZXh0"), 0o644); err != nil { //nolint:gosec // G306: the test needs a too-open fixture file
		t.Fatalf("write fixture: %v", err)
	}
	// WriteFile's mode is filtered by the process umask; chmod explicitly so
	// the fixture is wide-mode on any umask, not just 022.
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // G302: same too-open fixture as above
		t.Fatalf("chmod fixture: %v", err)
	}
	if _, err := readLocalRoot(path); err == nil {
		t.Fatal("readLocalRoot accepted a mode-0644 root key file")
	}
}

func TestReadRootKeyFileRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.key")
	if err := os.WriteFile(target, []byte("cGxhaW50ZXh0"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	link := filepath.Join(dir, "root.key")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink fixture: %v", err)
	}
	if _, err := readLocalRoot(link); err == nil {
		t.Fatal("readLocalRoot followed a symlink at the configured root key path")
	}
}

func TestReadRootKeyFileRefusesDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := readLocalRoot(dir); err == nil {
		t.Fatal("readLocalRoot accepted a directory path")
	}
}
