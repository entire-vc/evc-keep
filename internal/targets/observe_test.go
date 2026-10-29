//go:build unix

package targets

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

func observeKey(t *testing.T) fingerprint.Key {
	t.Helper()
	k, err := fingerprint.GenerateKey("obs")
	if err != nil {
		t.Fatal("key")
	}
	return k
}

func observeTarget(t *testing.T, body string) runnerproto.Target {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("resolve temp dir")
	}
	p := filepath.Join(dir, "app.env")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal("write carrier")
	}
	return runnerproto.Target{Kind: runnerproto.TargetFile, Path: p, Mode: 0o600}
}

func TestObserveReportsOnlyTheFingerprintOfWhatTheCarrierHolds(t *testing.T) {
	k := observeKey(t)
	tg := observeTarget(t, "synthetic-carrier-body")
	owner, exists, err := OwnerOf(tg, nil, nil)
	if err != nil || !exists || owner != int64(unix.Geteuid()) {
		t.Fatalf("OwnerOf: %d %v %v", owner, exists, err)
	}
	got, found, err := Observe(tg, owner, nil, nil, k)
	want, _ := fingerprint.Compute(k, secret.New([]byte("synthetic-carrier-body")))
	if err != nil || !found || !SameFingerprint(got, want) || SameFingerprint(got, want+"x") {
		t.Fatalf("Observe: %q %v %v", got, found, err)
	}
}

func TestObserveRefusesAnAgentOwnedCarrierAndAnUnverifiableKind(t *testing.T) {
	k := observeKey(t)
	tg := observeTarget(t, "synthetic-carrier-body")
	euid := int64(unix.Geteuid())
	if _, found, err := Observe(tg, euid, []int64{euid}, nil, k); err == nil || found {
		t.Fatal("a carrier owned by an agent was observed")
	}
	if _, found, err := Observe(tg, euid, nil, nil, k); err != nil || !found {
		t.Fatal("positive control: the same carrier is observed when its owner is not an agent")
	}
	sc := tg
	sc.Kind = runnerproto.TargetSystemdCredential
	if _, found, err := Observe(sc, euid, nil, nil, k); err == nil || found {
		t.Fatal("a systemd credential was observed")
	}
}

func TestOwnerOfDoesNotFollowASymlinkAndSaysAbsentForAMissingFile(t *testing.T) {
	tg := observeTarget(t, "synthetic-carrier-body")
	link := filepath.Join(filepath.Dir(tg.Path), "link.env")
	if err := os.Symlink(tg.Path, link); err != nil {
		t.Fatal("symlink")
	}
	if _, _, err := OwnerOf(runnerproto.Target{Kind: tg.Kind, Path: link}, nil, nil); err == nil {
		t.Fatal("a symlink carrier was followed")
	}
	if _, exists, err := OwnerOf(runnerproto.Target{Kind: tg.Kind, Path: tg.Path + ".none"}, nil, nil); err != nil || exists {
		t.Fatalf("a missing file must be reported absent: %v %v", exists, err)
	}
}

func TestOwnerOfRefusesWhatAnAgentCanWriteBeforeAnythingIsRead(t *testing.T) {
	tg := observeTarget(t, "synthetic-carrier-body")
	if _, exists, err := OwnerOf(tg, nil, nil); err != nil || !exists {
		t.Fatal("positive control: a 0600 carrier is reported")
	}
	if err := os.Chmod(tg.Path, 0o666); err != nil { //nolint:gosec // G302: the fixture is deliberately writable by everyone
		t.Fatal("chmod")
	}
	if _, _, err := OwnerOf(tg, nil, nil); err == nil {
		t.Fatal("a world-writable carrier was reported")
	}
	if err := os.Chmod(tg.Path, 0o660); err != nil { //nolint:gosec // G302: the fixture is deliberately group-writable
		t.Fatal("chmod")
	}
	if _, _, err := OwnerOf(tg, nil, []int64{int64(unix.Getegid())}); err == nil {
		t.Fatal("a carrier writable by an agent group was reported")
	}
}

func TestOwnerOfRefusesANonRegularCarrier(t *testing.T) {
	tg := observeTarget(t, "synthetic-carrier-body")
	fifo := filepath.Join(filepath.Dir(tg.Path), "pipe.env")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal("mkfifo")
	}
	if _, _, err := OwnerOf(runnerproto.Target{Kind: tg.Kind, Path: fifo}, nil, nil); err == nil {
		t.Fatal("a pipe was reported as a carrier")
	}
}

func TestOwnerOfRefusesAHardLinkedCarrier(t *testing.T) {
	tg := observeTarget(t, "synthetic-carrier-body")
	if err := os.Link(tg.Path, tg.Path+".twin"); err != nil {
		t.Fatal("link")
	}
	if _, _, err := OwnerOf(tg, nil, nil); err == nil {
		t.Fatal("a carrier with a second link was reported")
	}
}
