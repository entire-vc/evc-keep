package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/internal/runner/execrun"
)

func TestCheckExecHome(t *testing.T) {
	dir := t.TempDir()
	if err := checkExecHome(dir); err != nil {
		t.Fatalf("empty directory refused: %v", err)
	}
	full := t.TempDir()
	if err := os.WriteFile(filepath.Join(full, "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{
		"not-empty": full, "missing": filepath.Join(dir, "nope"), "relative": "exec-home",
		"unclean": dir + "/../" + filepath.Base(dir), "symlink": link, "empty-string": "",
	} {
		if err := checkExecHome(p); err == nil {
			t.Errorf("%s: accepted %q", name, p)
		}
	}
}

// A relative path to an existing empty directory is still refused: the child's
// HOME must not depend on where the runner was started.
func TestCheckExecHomeRefusesRelativePathToAnExistingDirectory(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := checkExecHome("."); err == nil {
		t.Fatal("relative path accepted")
	}
}

// A directory the runner cannot list is not known to be empty.
func TestCheckExecHomeRefusesAnUnreadableDirectory(t *testing.T) {
	old := readDir
	readDir = func(string) ([]os.DirEntry, error) { return nil, errors.New("permission denied") }
	t.Cleanup(func() { readDir = old })
	if err := checkExecHome(t.TempDir()); err == nil {
		t.Fatal("unreadable directory accepted")
	}
}

func TestExecSetup(t *testing.T) {
	home := t.TempDir()
	d, msg := execSetup(1234, 5678, home)
	if msg != "" || d == nil {
		t.Fatalf("valid flags refused: %q", msg)
	}
	ns, ok := d.Iso.(*execrun.Netns)
	if d.HomeRoot != home || !ok || ns.ChildUID != 1234 || ns.ChildGID != 5678 || d.ChildUID != 1234 || d.ChildGID != 5678 {
		t.Fatalf("deps do not carry the flags: %+v", d)
	}
	for name, c := range map[string]struct {
		uid, gid uint
		home     string
	}{
		"uid-0": {0, 5678, home}, "gid-0": {1234, 0, home}, "no-home": {1234, 5678, ""},
		"bad-home": {1234, 5678, "relative"},
	} {
		if d, msg := execSetup(c.uid, c.gid, c.home); msg == "" || d != nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A root the child can write to is a channel from one run to the next.
func TestCheckExecHomeRefusesARootOthersCanWriteOrNotOwnedByTheRunner(t *testing.T) {
	for _, mode := range []os.FileMode{0o770, 0o707, 0o777} {
		dir := t.TempDir()
		if err := os.Chmod(dir, mode); err != nil { //nolint:gosec // G302: the mode under test
			t.Fatal(err)
		}
		if err := checkExecHome(dir); err == nil {
			t.Errorf("mode %o accepted", mode)
		}
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: the mode a child needs to enter
		t.Fatal(err)
	}
	if err := checkExecHome(dir); err != nil {
		t.Fatalf("0755 root owned by the runner refused: %v", err)
	}
	old := ownerOf
	ownerOf = func(os.FileInfo) (int, bool) { return os.Geteuid() + 1, true }
	t.Cleanup(func() { ownerOf = old })
	if err := checkExecHome(dir); err == nil {
		t.Fatal("a root owned by another account accepted")
	}
}
