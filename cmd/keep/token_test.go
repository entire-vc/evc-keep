package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveToken_EnvTakesPrecedenceOverFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("keep_a_fromfile"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveToken(func(k string) string {
		if k == "KEEP_TOKEN" {
			return "keep_a_fromenv"
		}
		return ""
	}, path)
	if err != nil || got != "keep_a_fromenv" {
		t.Fatalf("resolveToken() = %q, %v, want the env value", got, err)
	}
}

// TestResolveToken_RefusesWidePermissions is red run (2) from the card's
// AC: a 0644 token file must be refused. scripts/check-keep-cli-mutations.sh
// removes the permission check and requires this test to go red.
func TestResolveToken_RefusesWidePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("keep_a_secret"), 0o644); err != nil { //nolint:gosec // G306: the wide-open mode is the point of this test — it must be refused
		t.Fatal(err)
	}
	if _, err := resolveToken(func(string) string { return "" }, path); err == nil {
		t.Fatal("resolveToken() with a 0644 token file must refuse, got a nil error")
	}
}

func TestResolveToken_RefusesGroupReadableEvenWithoutOtherAccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("keep_a_secret"), 0o640); err != nil { //nolint:gosec // G306: the group-readable mode is the point of this test — it must be refused
		t.Fatal(err)
	}
	if _, err := resolveToken(func(string) string { return "" }, path); err == nil {
		t.Fatal("resolveToken() with a 0640 (group-readable) token file must refuse, got a nil error")
	}
}

// TestResolveToken_AcceptsOwnerOnlyPermissions is the positive control for
// (2): the same check must not refuse the mode the card actually asks for.
func TestResolveToken_AcceptsOwnerOnlyPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("keep_a_secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveToken(func(string) string { return "" }, path)
	if err != nil || got != "keep_a_secret" {
		t.Fatalf("resolveToken() = %q, %v, want the file's trimmed content", got, err)
	}
}

func TestResolveToken_NoTokenAnywhere(t *testing.T) {
	if _, err := resolveToken(func(string) string { return "" }, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("resolveToken() with nothing configured must error, got nil")
	}
}

func TestRunLogin_WritesFileWithOwnerOnlyMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "token")
	if err := runLogin(path, "keep_a_mine"); err != nil {
		t.Fatalf("runLogin() = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != tokenFilePerm {
		t.Fatalf("token file mode = %04o, want %04o", perm, tokenFilePerm)
	}
	got, err := os.ReadFile(path) //nolint:gosec // G304: path is this test's own t.TempDir() path
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep_a_mine\n" {
		t.Fatalf("token file content = %q", got)
	}
}

// TestRunLogin_FixesModeOfPreExistingLooseFile: os.WriteFile only applies
// its mode when it CREATES a file, so a naive `os.WriteFile(path, data,
// 0600)` on a pre-existing 0644 file would silently leave it at 0644 — this
// pins the explicit chmod that avoids that trap.
func TestRunLogin_FixesModeOfPreExistingLooseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil { //nolint:gosec // G306: the loose pre-existing mode is the point of this test — runLogin must fix it up
		t.Fatal(err)
	}
	if err := runLogin(path, "keep_a_new"); err != nil {
		t.Fatalf("runLogin() = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != tokenFilePerm {
		t.Fatalf("token file mode = %04o, want %04o even though it pre-existed looser", perm, tokenFilePerm)
	}
}

func TestRunLogin_RejectsEmptyToken(t *testing.T) {
	if err := runLogin(filepath.Join(t.TempDir(), "token"), "   "); err == nil {
		t.Fatal("runLogin() with a blank token must error, got nil")
	}
}
