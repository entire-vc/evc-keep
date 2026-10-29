//go:build unix

package targets

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"golang.org/x/sys/unix"
)

// openFDCount counts how many low-numbered file descriptors are currently
// valid — the same range openFDsWithoutCloexec (guards2_test.go) scans. A
// directory descriptor Write opens but never closes moves this number by
// exactly the number of leaks.
func openFDCount() int {
	n := 0
	for fd := 3; fd < 200; fd++ {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
			n++
		}
	}
	return n
}

// TestWriteDoesNotLeakDirectoryDescriptors: walkToParent opens one
// descriptor per path component on the way down and Write itself holds the
// parent's descriptor (write.go's own defer) across the whole call. Every
// one of them must be closed by the time Write returns — a directory
// descriptor leaked on every job this process runs is eventually EMFILE, an
// availability failure on a security-critical path. The target directory is
// nested several levels deep so the walk's own per-component close (every
// non-final Openat immediately closes the descriptor it just replaced) runs
// more than once per call, not just Write's single deferred close of the
// final parent.
func TestWriteDoesNotLeakDirectoryDescriptors(t *testing.T) {
	dir := realDir(t)
	nested := filepath.Join(dir, "a", "b", "c", "d")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	uids, gids := noAgents()
	const n = 25
	before := openFDCount()
	for i := 0; i < n; i++ {
		path := filepath.Join(nested, fmt.Sprintf("target-%d", i))
		if _, err := Write(target(runnerproto.TargetFile, path, ""), newValue("v"), uids, gids, testFPKey(t)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	after := openFDCount()
	if after != before {
		t.Fatalf("open descriptor count moved from %d to %d after %d writes", before, after, n)
	}
}

// TestWriteDoesNotLeakDirectoryDescriptorsOnRefusal is the refusal-path
// twin of TestWriteDoesNotLeakDirectoryDescriptors. The refusal has to come
// from envFileHandler.build (a newline is not a byte an env-file value can
// hold): that check runs only after walkToParent and readExisting have
// already succeeded and write.go's deferred close of the parent descriptor
// is already registered, so both the per-component closes inside the walk
// and that deferred close are live on this path. A target-mode or
// directory-policy refusal would not do: those fire inside
// validateTargetPerm or walkToParent itself, before or without ever
// reaching write.go's defer, so they would pass this test even with the
// defer deleted — proving nothing about the leak the mutants below inject.
func TestWriteDoesNotLeakDirectoryDescriptorsOnRefusal(t *testing.T) {
	dir := realDir(t)
	nested := filepath.Join(dir, "a", "b", "c", "d")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	uids, gids := noAgents()
	const n = 25
	before := openFDCount()
	for i := 0; i < n; i++ {
		path := filepath.Join(nested, fmt.Sprintf("target-%d", i))
		tg := target(runnerproto.TargetEnvFile, path, "SECRET")
		if _, err := Write(tg, newValue("line-one\nline-two"), uids, gids, testFPKey(t)); err == nil {
			t.Fatalf("write %d: expected refusal for a newline in the value, got nil error", i)
		}
	}
	after := openFDCount()
	if after != before {
		t.Fatalf("open descriptor count moved from %d to %d after %d refused writes", before, after, n)
	}
}
