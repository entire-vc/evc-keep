package builtin

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestNewLocalConsumesRoot(t *testing.T) {
	for _, id := range []string{"test-root", ""} {
		t.Run(id, func(t *testing.T) {
			raw := bytes.Repeat([]byte{'*'}, 32)
			local, err := NewLocal(nil, id, raw, nil, nopAudit)
			if (id == "") != (err != nil) || (id != "" && local == nil) {
				t.Fatal("constructor outcome control failed")
			}
			if !bytes.Equal(raw, make([]byte, len(raw))) {
				t.Fatal("consumed root buffer was not wiped")
			}
		})
	}
}

func TestLocalRootFileSafety(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.key")
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal(nil, path, nil, nopAudit); err != nil {
		t.Fatal("private root file rejected")
	}
	alias := path + ".link"
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal(nil, alias, nil, nopAudit); err == nil {
		t.Fatal("symlink root accepted")
	}
	if err := os.Chmod(path, 0644); err != nil { // #nosec G302 -- negative control for unsafe root-key permissions
		t.Fatal(err)
	}
	if _, err := OpenLocal(nil, path, nil, nopAudit); err == nil {
		t.Fatal("public root file accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw[:31], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal(nil, path, nil, nopAudit); err == nil {
		t.Fatal("truncated root accepted")
	}
}

func TestLocalRootRejectsZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zero.key")
	if err := os.WriteFile(path, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if local, err := OpenLocal(nil, path, nil, nopAudit); err == nil || local != nil {
		t.Fatal("zero root accepted")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if local, err := OpenLocal(nil, path, nil, nopAudit); err != nil || local == nil {
		t.Fatal("nonzero root rejected")
	}
}
