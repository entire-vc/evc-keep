//go:build unix

// Shared fixtures for the external attacks on internal/targets (
// stale temporary files, ancestor ACLs, systemd-credential plaintext
// fallback). Only the exported API is used: targets.Write, its Options and
// the error sentinels; nothing in the package's test hooks.
package targets_test

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"golang.org/x/sys/unix"

	cnry "github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/runnerproto"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// tgtRealDir is a fresh temp dir with symlinks resolved (/var on macOS is a
// symlink, and Write refuses any symlink on the path) and owned by this
// process's group, mode 0700.
func tgtRealDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(d, -1, unix.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o700); err != nil { //nolint:gosec // G302: a directory needs x; 0700 is owner-only
		t.Fatal(err)
	}
	return d
}

func tgtTarget(kind runnerproto.TargetKind, path string) runnerproto.Target {
	return runnerproto.Target{
		Kind: kind,
		Path: path,
		Mode: 0o600,
		UID:  int64(unix.Geteuid()),
		GID:  int64(unix.Getegid()),
	}
}

func tgtKey(t *testing.T) fingerprint.Key {
	t.Helper()
	k, err := fingerprint.GenerateKey("atk81")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// tgtNoAgents: no agent uid/gid declared — directory checks never fire on a
// 0700 tree, so a refusal can only come from the check under attack.
func tgtNoAgents() ([]int64, []int64) { return nil, nil }

func tgtValue(s string) secret.Value { return secret.New([]byte(s)) }

var b64Token = regexp.MustCompile(`[A-Za-z0-9+/_-]{8,}={0,2}`)

// tgtLeaks reports whether s carries the canary in any encoding cnry.In
// knows, plus any base64 token decoded by hand (cnry.In is blind to
// base64 at offsets 1-2 mod 3).
func tgtLeaks(c cnry.Canary, s string) bool {
	if c.In(s) {
		return true
	}
	for _, tok := range b64Token.FindAllString(s, -1) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(tok); err == nil && c.In(string(b)) {
				return true
			}
		}
	}
	return false
}

// tgtErrLeaks checks every way a caller may render an error.
func tgtErrLeaks(c cnry.Canary, err error) bool {
	if err == nil {
		return false
	}
	for _, s := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err), fmt.Sprintf("%q", err)} {
		if tgtLeaks(c, s) {
			return true
		}
	}
	return false
}

// tgtDirHolds reports whether any regular file directly in dir carries the
// canary. Symlinks and FIFOs are not opened.
func tgtDirHolds(t *testing.T, dir string, c cnry.Canary) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var hits []string
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // G304: test-controlled path
		if err != nil {
			t.Fatal(err)
		}
		if tgtLeaks(c, string(b)) {
			hits = append(hits, e.Name())
		}
	}
	return hits
}
