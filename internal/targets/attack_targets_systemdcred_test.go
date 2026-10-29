//go:build unix

// Attacks on the systemd-credential target without systemd-creds (threat
// model 7.4 "no silent drop to less protection", I6 downgrade;
// HostPolicy.SystemdCredPlaintextFallback). Without the policy flag the
// target is refused as policy (ErrPolicy), nothing lands on disk and no
// error rendering carries the value. With the flag a 0600 plain file is
// written and the fallback is announced with the path only.
package targets_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/entire-vc/evc-keep/internal/targets"
	cnry "github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
)

func requireNoSystemdCreds(t *testing.T) {
	t.Helper()
	if _, err := os.Lstat("/usr/bin/systemd-creds"); err == nil {
		t.Skip("host has /usr/bin/systemd-creds: the no-binary path cannot be exercised here")
	}
}

// TestTargetsSystemdCred_NoBinaryRefusedByDefault — I6 / threat model 7.4.
// Positive control: the same value to a "file" target in a sibling dir is
// written, so the refusal is not a broken fixture.
func TestTargetsSystemdCred_NoBinaryRefusedByDefault(t *testing.T) {
	requireNoSystemdCreds(t)
	c := cnry.New()
	ctl := tgtRealDir(t)
	if err := writeFile(t, ctl, "control", c.Value(0)); err != nil {
		t.Fatalf("positive control: file target refused: %v", err)
	}

	dir := tgtRealDir(t)
	u, g := tgtNoAgents()
	res, err := targets.Write(tgtTarget(runnerproto.TargetSystemdCredential, filepath.Join(dir, "cred")), tgtValue(c.Value(0)), u, g, tgtKey(t))
	if err == nil {
		t.Fatalf("systemd-credential without systemd-creds and without the policy flag was written (result %q)", res)
	}
	if !errors.Is(err, targets.ErrPolicy) {
		t.Fatalf("want ErrPolicy, got %v", err)
	}
	if errors.Is(err, targets.ErrWrite) || errors.Is(err, targets.ErrUnconfirmed) {
		t.Fatalf("refusal must be a policy class only, got %v", err)
	}
	if res != "" {
		t.Fatalf("refused write returned a result %q", res)
	}
	if tgtErrLeaks(c, err) {
		t.Fatal("value reached the error text")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("refused write left entries %v", names)
	}
}

// TestTargetsSystemdCred_FallbackWritesOwnerOnly — HostPolicy flag set: a
// plain file at 0600 holding the value; the returned fingerprint and the
// notice carry no value; the notice is the target path.
func TestTargetsSystemdCred_FallbackWritesOwnerOnly(t *testing.T) {
	requireNoSystemdCreds(t)
	c := cnry.New()
	dir := tgtRealDir(t)
	p := filepath.Join(dir, "cred")
	var notices []string
	u, g := tgtNoAgents()
	res, err := targets.Write(tgtTarget(runnerproto.TargetSystemdCredential, p), tgtValue(c.Value(0)), u, g, tgtKey(t),
		targets.WithSystemdCredPlaintextFallback(func(path string) { notices = append(notices, path) }))
	if err != nil {
		t.Fatalf("Write with fallback: %v", err)
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("fallback file mode = %v, want regular 0600", fi.Mode())
	}
	b, _ := os.ReadFile(p) //nolint:gosec // G304: test path
	if string(b) != c.Value(0) {
		t.Fatal("fallback file does not hold exactly the value")
	}
	if tgtLeaks(c, res) || tgtLeaks(c, fmt.Sprint(notices)) {
		t.Fatal("value reached the result or the notice")
	}
	if len(notices) != 1 || notices[0] != p {
		t.Fatalf("notices = %v, want exactly [%s]", notices, p)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("fallback left %d entries, want only the target", len(ents))
	}
}

// TestTargetsSystemdCred_FallbackDoesNotStick — I6. The flag is per call:
// a Write with the option must not leave the writer in fallback mode for
// the next Write without it (no global state downgrade).
func TestTargetsSystemdCred_FallbackDoesNotStick(t *testing.T) {
	requireNoSystemdCreds(t)
	c := cnry.New()
	u, g := tgtNoAgents()
	d1 := tgtRealDir(t)
	if _, err := targets.Write(tgtTarget(runnerproto.TargetSystemdCredential, filepath.Join(d1, "cred")), tgtValue(c.Value(0)), u, g, tgtKey(t),
		targets.WithSystemdCredPlaintextFallback(nil)); err != nil {
		t.Fatalf("positive control: fallback write: %v", err)
	}
	d2 := tgtRealDir(t)
	_, err := targets.Write(tgtTarget(runnerproto.TargetSystemdCredential, filepath.Join(d2, "cred")), tgtValue(c.Value(1)), u, g, tgtKey(t))
	if !errors.Is(err, targets.ErrPolicy) {
		t.Fatalf("second Write without the flag: want ErrPolicy, got %v", err)
	}
	if ents, _ := os.ReadDir(d2); len(ents) != 0 {
		t.Fatal("second Write without the flag left a file")
	}
}

// TestTargetsSystemdCred_FallbackModeNeverWiderThan0600 — the plaintext
// fallback must produce an owner-only file even when the target asks for
// 0640 (the card and HostPolicy say "plain 0600").
func TestTargetsSystemdCred_FallbackModeNeverWiderThan0600(t *testing.T) {
	requireNoSystemdCreds(t)
	c := cnry.New()
	dir := tgtRealDir(t)
	p := filepath.Join(dir, "cred")
	u, g := tgtNoAgents()
	tg := tgtTarget(runnerproto.TargetSystemdCredential, p)
	tg.Mode = 0o640
	_, err := targets.Write(tg, tgtValue(c.Value(0)), u, g, tgtKey(t),
		targets.WithSystemdCredPlaintextFallback(func(string) {}))
	if err != nil {
		return // refusing a group-readable plaintext file is also acceptable
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("plaintext fallback written with mode %v, want 0600 or refusal", fi.Mode().Perm())
	}
}
