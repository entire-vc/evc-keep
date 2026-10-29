package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteTokenFile(t *testing.T) {
	tok, err := GenerateToken(KindUser)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	dest := filepath.Join(dir, "admin.token")
	if err := WriteTokenFile(dest, tok); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %o, want 600", fi.Mode().Perm())
	}
	b, err := os.ReadFile(dest) //nolint:gosec // G304: the test's own temp path
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != Reveal(tok)+"\n" {
		t.Error("file does not hold the token and a newline")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("directory holds %d entries, want only the token file", len(ents))
	}

	// An existing file is kept as it was.
	if err := WriteTokenFile(dest, NewToken("other")); err == nil {
		t.Error("writing over an existing file must fail")
	}
	if b2, _ := os.ReadFile(dest); string(b2) != string(b) { //nolint:gosec // G304: the test's own temp path
		t.Error("existing file was changed")
	}
}
