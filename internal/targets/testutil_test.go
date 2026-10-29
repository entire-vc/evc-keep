//go:build unix

package targets

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
	"golang.org/x/sys/unix"
)

// realDir returns a fresh, absolute test directory with every macOS symlink
// on its path already resolved (t.TempDir() on macOS sits under /var,
// itself a symlink to /private/var — Write's own O_NOFOLLOW walk would
// otherwise refuse every "should succeed" test the same way it refuses a
// deliberately planted symlink; TestVarIsASymlinkOnDarwin below turns that
// exact gotcha into the positive control for the symlink defense instead of
// working around it silently).
func realDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("resolve tempdir: %v", err)
	}
	// Tests declare this process's egid as "the agent group" and expect the
	// directories they create to belong to it. A new directory takes its
	// parent's group on macOS, so a TMPDIR whose group is another one (wheel
	// under /private/tmp) would turn those tests red with no defect behind it.
	if err := os.Chown(resolved, -1, unix.Getegid()); err != nil {
		t.Fatalf("give the tempdir to the process group: %v", err)
	}
	return resolved
}

// fsyncFreeDir is realDir for a test that performs thousands of Writes (each
// fsyncs) and execs only the system shell: when KEEP_TEST_TMPFS names a
// directory (CI points it at tmpfs, where one fsync costs nothing, instead
// of the shared runner disk where one costs seconds) the test directory is
// created there. Unset, it is exactly realDir. The directory must allow
// no exec: nothing runs from it.
func fsyncFreeDir(t *testing.T) string {
	t.Helper()
	base := os.Getenv("KEEP_TEST_TMPFS")
	if base == "" {
		return realDir(t)
	}
	dir, err := os.MkdirTemp(base, "keep-test-")
	if err != nil {
		t.Fatalf("create test dir under KEEP_TEST_TMPFS: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) }) //nolint:gosec // test-only path under KEEP_TEST_TMPFS
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("resolve test dir: %v", err)
	}
	if err := os.Chown(resolved, -1, unix.Getegid()); err != nil { //nolint:gosec // test-only path under KEEP_TEST_TMPFS
		t.Fatalf("give the test dir to the process group: %v", err)
	}
	return resolved
}

// selfUID/selfGID stand in for "an agent uid/gid": files this test process
// creates are owned by them, so declaring them as the agent set is exactly
// equivalent to a real second account owning the file — the code only ever
// compares the numbers.
func selfUID() int64 { return int64(unix.Geteuid()) }
func selfGID() int64 { return int64(unix.Getegid()) }

// uidT narrows a uid back to the uint32 that unix.Stat_t.Uid actually holds,
// for tests building a synthetic Stat_t from selfUID(). The OS never hands
// out a euid outside uint32 range — Geteuid's own return type is a signed
// int only because that's the libc convention — so the bounds check here
// never fires; it exists so the int64->uint32 narrowing is a checked,
// explained conversion instead of a bare cast gosec has to flag blind.
func uidT(t *testing.T, uid int64) uint32 {
	t.Helper()
	if uid < 0 || uid > math.MaxUint32 {
		t.Fatalf("uid %d out of uint32 range", uid)
	}
	return uint32(uid) // #nosec G115 -- bounds-checked immediately above
}

func noAgents() ([]int64, []int64) { return nil, nil }
func selfAsAgent() ([]int64, []int64) {
	return []int64{selfUID()}, []int64{selfGID()}
}

// syntheticAgentUID/GID are numbers that do not belong to any real account
// on this host. Used where a test must declare "an agent" without that
// agent also being the directory's real owner (which selfUID/selfGID would
// be) — otherwise the directory-level checks (agents.go) would catch the
// same scenario first and mask whatever this test means to isolate.
// validateTargetPerm never chowns to these (the write is refused before it
// gets that far), so they need not be real.
const syntheticAgentUID = 1 << 30
const syntheticAgentGID = 1<<30 + 1

// safeDir returns a fresh subdirectory of realDir(t) with mode 0700: no
// group or other access at all, so directory-level agent checks never fire
// on it and a test can isolate a target-level check instead.
func safeDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(realDir(t), "safe")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func testFPKey(t *testing.T) fingerprint.Key {
	t.Helper()
	k, err := fingerprint.GenerateKey("teststore")
	if err != nil {
		t.Fatalf("generate fingerprint key: %v", err)
	}
	return k
}

func mustWriteFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: test-controlled path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// target builds a plain deploy target under mode 0600, owner selfUID/selfGID
// — a target that should succeed to write unless a test overrides a field.
func target(kind runnerproto.TargetKind, path, field string) runnerproto.Target {
	return runnerproto.Target{
		Kind:  kind,
		Path:  path,
		Field: field,
		Mode:  0o600,
		UID:   selfUID(),
		GID:   selfGID(),
	}
}

func wantErr(t *testing.T, err error, sentinel error, context string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: want error wrapping %v, got nil", context, sentinel)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("%s: want error wrapping %v, got %v", context, sentinel, err)
	}
}

func newValue(s string) secret.Value { return secret.New([]byte(s)) }
