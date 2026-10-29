//go:build unix

package targets

import (
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

// TestEnvFileNeighboringLinesByteIdentical checks that writing
// one NAME=value line leaves every other line exactly as it was, byte for
// byte.
func TestEnvFileNeighboringLinesByteIdentical(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "app.env")
	before := "# a comment, kept as-is\nFOO=bar\nEMPTY=\nWEIRD='  spaced  '\nTARGET=old-value\nZZZ=last\n"
	mustWriteFile(t, path, []byte(before), 0o600)

	uids, gids := noAgents()
	fp, err := Write(target(runnerproto.TargetEnvFile, path, "TARGET"), newValue("new-value"), uids, gids, testFPKey(t))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !fingerprint.Valid(fp) {
		t.Fatalf("fingerprint %q is not valid kfp1", fp)
	}

	got := string(mustReadFile(t, path))
	want := "# a comment, kept as-is\nFOO=bar\nEMPTY=\nWEIRD='  spaced  '\nTARGET=new-value\nZZZ=last\n"
	if got != want {
		t.Fatalf("neighboring lines changed:\n got:  %s\n want: %s", show([]byte(got)), show([]byte(want)))
	}
}

func TestEnvFileAppendsWhenFieldMissing(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "app.env")
	mustWriteFile(t, path, []byte("FOO=bar\n"), 0o600)

	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetEnvFile, path, "NEW"), newValue("v"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := string(mustReadFile(t, path))
	want := "FOO=bar\nNEW=v\n"
	if got != want {
		t.Fatalf("got %s, want %s", show([]byte(got)), show([]byte(want)))
	}
}

func TestEnvFileCreatesWhenMissing(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "fresh.env")
	uids, gids := noAgents()
	if _, err := Write(target(runnerproto.TargetEnvFile, path, "NEW"), newValue("v"), uids, gids, testFPKey(t)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, want := string(mustReadFile(t, path)), "NEW=v\n"; got != want {
		t.Fatalf("got %s, want %s", show([]byte(got)), show([]byte(want)))
	}
}

func TestEnvFileRejectsNewlineInValue(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "app.env")
	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetEnvFile, path, "X"), newValue("a\nb"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrPolicy, "value with an embedded newline")
}

func TestEnvFileFingerprintRoundTrips(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "app.env")
	key := testFPKey(t)
	uids, gids := noAgents()
	fp, err := Write(target(runnerproto.TargetEnvFile, path, "X"), newValue("round-trip-value"), uids, gids, key)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	want, err := fingerprint.Compute(key, newValue("round-trip-value"))
	if err != nil {
		t.Fatal(err)
	}
	if fp != want {
		t.Fatalf("fingerprint %q does not match direct Compute %q", fp, want)
	}
}

// TestEnvFileDuplicateLineRefused: a pre-existing, malformed file with two
// lines for the same field is refused rather than silently rotating only
// the first and leaving a stale second copy of the old value behind — a
// secrets manager leaving an old value reachable after a "successful"
// rotation is exactly the kind of thing this package exists to prevent.
func TestEnvFileDuplicateLineRefused(t *testing.T) {
	dir := realDir(t)
	path := filepath.Join(dir, "app.env")
	mustWriteFile(t, path, []byte("TARGET=first\nOTHER=x\nTARGET=second\n"), 0o600)

	uids, gids := noAgents()
	_, err := Write(target(runnerproto.TargetEnvFile, path, "TARGET"), newValue("new"), uids, gids, testFPKey(t))
	wantErr(t, err, ErrWrite, "pre-existing duplicate field lines")

	if got := string(mustReadFile(t, path)); got != "TARGET=first\nOTHER=x\nTARGET=second\n" {
		t.Fatalf("file was modified despite the refusal: %q", show([]byte(got)))
	}
}
