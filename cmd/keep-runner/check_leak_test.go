//go:build unix

package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// The policy file is arbitrary text, so keep-runner check must not echo a
// prefix, a path component, a resolved path or an Lstat error from it: only a
// class and the rule/prefix indexes. The canary sits in the policy prefix.
// A failure message never prints the output, which would be the leak itself.
func TestCheckNeverEchoesPolicyPrefixContent(t *testing.T) {
	bin := buildBinary(t, "github.com/entire-vc/evc-keep/cmd/keep-runner", "keep-runner")
	c := canary.New()
	if !c.In("x "+c.Value(1)) || !c.In(hex.EncodeToString([]byte(c.Value(1)))) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	h := newPrefixHost(t)

	name := c.Value(1)
	cases := []struct {
		class, prefix string
	}{}
	// symlink named by the canary, pointing at a real directory.
	link := filepath.Join(h.base, name+"-link")
	if err := os.Symlink(h.realDir, link); err != nil {
		t.Fatal(err)
	}
	cases = append(cases, struct{ class, prefix string }{"symlink", filepath.Join(link, "ext")})
	// a regular file in the middle of the prefix.
	file := filepath.Join(h.base, name+"-file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases = append(cases, struct{ class, prefix string }{"not_directory", filepath.Join(file, "ext")})
	// a component over NAME_MAX: Lstat fails with ENAMETOOLONG, which is not
	// "does not exist" and needs no directory mode, so it also holds as root.
	long := filepath.Join(h.base, name+strings.Repeat("a", 300))
	cases = append(cases, struct{ class, prefix string }{"lstat_error", filepath.Join(long, "ext")})

	for _, tc := range cases {
		t.Run(tc.class, func(t *testing.T) {
			var out bytes.Buffer
			cmd := exec.Command(bin, "check", "-cred-dir", h.credDir, "-policy", h.policy(t, tc.class+".json", tc.prefix)) //nolint:gosec // G204: this test's own build output and fixture paths
			cmd.Stdout, cmd.Stderr = &out, &out
			err := cmd.Run()
			ee, ok := err.(*exec.ExitError)
			if !ok || ee.ExitCode() != 1 {
				t.Fatalf("expected exit 1, got %v", err)
			}
			if c.In(out.String()) || strings.Contains(out.String(), h.base) {
				t.Errorf("policy prefix content reached the terminal (%d bytes)", out.Len())
			}
			// Useful category: class and indexes, not content.
			want := "policy rule 0 prefix 0 is refused (" + tc.class + ")"
			if !strings.Contains(out.String(), want) {
				t.Errorf("output lacks the safe category %q", want)
			}
		})
	}
}

// The -cred-dir value (a flag the operator typed) stays off stderr when the
// credential cannot be loaded.
func TestCheckCredDirNeverEchoedOnLoadFailure(t *testing.T) {
	bin := buildBinary(t, "github.com/entire-vc/evc-keep/cmd/keep-runner", "keep-runner")
	c := canary.New()
	h := newPrefixHost(t)
	dir := filepath.Join(h.base, c.Value(1))
	var out bytes.Buffer
	cmd := exec.Command(bin, "check", "-cred-dir", dir, "-policy", h.policy(t, "ok.json", filepath.Join(h.realDir, "ext"))) //nolint:gosec // G204: this test's own build output and fixture paths
	cmd.Stdout, cmd.Stderr = &out, &out
	ee, ok := cmd.Run().(*exec.ExitError)
	if !ok || ee.ExitCode() != 1 || out.Len() == 0 {
		t.Fatalf("expected exit 1 with a message, got %v", ok)
	}
	if !c.In("x "+dir) || c.In(out.String()) {
		t.Errorf("-cred-dir value reached the terminal or detector is blind (%d bytes)", out.Len())
	}
}
