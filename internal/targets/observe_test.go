//go:build unix

package targets

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
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

func TestObserveRefusesAnAgentOwnedCarrier(t *testing.T) {
	k := observeKey(t)
	tg := observeTarget(t, "synthetic-carrier-body")
	euid := int64(unix.Geteuid())
	if _, found, err := Observe(tg, euid, []int64{euid}, nil, k); err == nil || found {
		t.Fatal("a carrier owned by an agent was observed")
	}
	if _, found, err := Observe(tg, euid, nil, nil, k); err != nil || !found {
		t.Fatal("positive control: the same carrier is observed when its owner is not an agent")
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

// namedCreds is a stand-in for systemd-creds that binds the credential to the
// --name given at encrypt, as the real tool does: decrypt under another name
// fails. The sealed form is the name line, then the value.
func namedCreds(t *testing.T) {
	t.Helper()
	dir := realDir(t)
	bin := filepath.Join(dir, "systemd-creds")
	script := "#!/bin/sh\nn=${2#--name=}\ncase $1 in\nencrypt) printf 'sealed-for=%s\\n' \"$n\"; cat;;\ndecrypt) read -r l; [ \"$l\" = \"sealed-for=$n\" ] || exit 1; cat;;\n*) exit 2;;\nesac\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil { //nolint:gosec // G306: an executable test double
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o755); err != nil { //nolint:gosec // G302: same reason
		t.Fatal(err)
	}
	origPath, origUID := sealToolPath, sealToolTrustedUID
	t.Cleanup(func() { sealToolPath, sealToolTrustedUID = origPath, origUID })
	sealToolPath, sealToolTrustedUID = bin, selfUID()
}

func writtenCredential(t *testing.T, v string) (runnerproto.Target, fingerprint.Key, string) {
	t.Helper()
	k := observeKey(t)
	dir := realDir(t)
	tg := credTarget(filepath.Join(dir, "cred"))
	uids, gids := noAgents()
	fp, err := Write(tg, newValue(v), uids, gids, k)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	return tg, k, fp
}

// The value of a systemd credential never leaves Observe: not in its result,
// not in an error, whether the credential decrypts or not.
func TestObserveSystemdCredentialLeaksNothing(t *testing.T) {
	namedCreds(t)
	c := canary.New()
	tg, k, _ := writtenCredential(t, c.Value(0))
	owner := int64(unix.Geteuid())
	fp, found, err := Observe(tg, owner, nil, nil, k)
	if !found || err != nil || c.In(fp) {
		t.Fatalf("Observe: found=%v err=%v", found, err)
	}
	wrong := tg
	wrong.Unit = "other.service"
	fp, found, err = Observe(wrong, owner, nil, nil, k)
	if c.In(fp) || (err != nil && c.In(err.Error())) || found {
		t.Fatal("the value or a hit came out of a failed decrypt")
	}
	if !strings.HasPrefix(string(mustReadFile(t, tg.Path)), "sealed-for=") {
		t.Fatal("control: the stand-in sealed nothing")
	}
}

func TestObserveSystemdCredentialMatchesOnlyUnderItsName(t *testing.T) {
	namedCreds(t)
	tg, k, want := writtenCredential(t, "synthetic-credential-value")
	owner := int64(unix.Geteuid())
	got, found, err := Observe(tg, owner, nil, nil, k)
	if err != nil || !found || !SameFingerprint(got, want) {
		t.Fatalf("a credential written under its unit must verify: %q %v %v", got, found, err)
	}
	wrong := tg
	wrong.Unit = "other.service"
	if got, found, err := Observe(wrong, owner, nil, nil, k); err != nil || found || got != "" {
		t.Fatalf("a credential must not verify under another name: %q %v %v", got, found, err)
	}
	none := tg
	none.Unit = ""
	if _, found, _ := Observe(none, owner, nil, nil, k); found {
		t.Fatal("a credential must not verify with no name")
	}
}

func TestObserveSystemdCredentialUntrustedToolIsPolicy(t *testing.T) {
	namedCreds(t)
	tg, k, _ := writtenCredential(t, "synthetic-credential-value")
	if err := os.Chmod(sealToolPath, 0o757); err != nil { //nolint:gosec // G302: the untrusted mode is the scenario
		t.Fatal(err)
	}
	_, found, err := Observe(tg, int64(unix.Geteuid()), nil, nil, k)
	if found || !errors.Is(err, ErrPolicy) {
		t.Fatalf("an untrusted decrypt tool must be a policy refusal, not a mismatch: found=%v err=%v", found, err)
	}
}
