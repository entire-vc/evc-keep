//go:build unix

package targets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

func TestFileKindWritesValueAsIs(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "raw")
	mustWriteFile(t, path, []byte("old content, fully replaced"), 0o600)

	uids, gids := noAgents()
	key := testFPKey(t)
	fp, err := Write(target(runnerproto.TargetFile, path, ""), newValue("exact bytes\x00\x01\xffmixed"), uids, gids, key)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, want := string(mustReadFile(t, path)), "exact bytes\x00\x01\xffmixed"; got != want {
		t.Fatalf("got %s, want %s", show([]byte(got)), show([]byte(want)))
	}
	want, err := fingerprint.Compute(key, newValue("exact bytes\x00\x01\xffmixed"))
	if err != nil {
		t.Fatal(err)
	}
	if fp != want {
		t.Fatalf("fingerprint mismatch")
	}
}

func TestFileTargetModeAndOwnerApplied(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "raw")
	tg := target(runnerproto.TargetFile, path, "")
	tg.Mode = 0o640
	uids, gids := noAgents()
	if _, err := Write(tg, newValue("v"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, want 0640", fi.Mode().Perm())
	}
}
