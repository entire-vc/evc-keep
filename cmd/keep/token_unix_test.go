//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveToken_RefusesSymlink is the red run for the symlink-refusal
// decision above: without O_NOFOLLOW, a symlink at the configured token
// path is followed and its target's content is read and returned as the
// bearer token — whatever that target is, not necessarily anything the
// caller meant to expose.
// scripts/check-keep-cli-mutations.sh's symlink-followed mutant reverts
// openTokenFileNoFollow to a plain os.Open and requires this test to go red.
func TestResolveToken_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("not_a_real_token"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "token")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveToken(func(string) string { return "" }, link); err == nil {
		t.Fatalf("resolveToken() over a symlink = %q, nil, want a refusal", got)
	}
}
