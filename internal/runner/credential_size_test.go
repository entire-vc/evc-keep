//go:build unix

// Diagnostics in this file are deliberately static: a failing assertion must
// never print the Load error, which on a leaking mutant carries PEM content.
package runner

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// padKeyFile rewrites the saved key file as its valid PEM, then filler
// newlines up to exactly total bytes (pem.Decode ignores trailing data, so
// the prefix stays a valid key), keeping mode 0600.
func padKeyFile(t *testing.T, dir string, total int) {
	t.Helper()
	p := filepath.Join(dir, keyFileName)
	pemBytes, err := os.ReadFile(p) //nolint:gosec // G304: test temp dir
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if len(pemBytes) > total {
		t.Fatalf("fixture: PEM (%d) longer than target size %d", len(pemBytes), total)
	}
	out := append(bytes.Clone(pemBytes), bytes.Repeat([]byte("\n"), total-len(pemBytes))...)
	if err := os.WriteFile(p, out, 0o600); err != nil { //nolint:gosec // G703: path is in the test temp dir
		t.Fatalf("write padded key file: %v", err)
	}
}

// TestLoadCredentialRefusesOversizeFile: a credential file past the 1 MiB
// cap is refused, not silently truncated to its first MiB and accepted on
// the strength of a valid prefix. The exact cap is accepted, cap+1 is not;
// the error is static (no file content, no byte count of the content).
func TestLoadCredentialRefusesOversizeFile(t *testing.T) {
	const limit = 1 << 20

	// Positive control: an ordinary credential loads.
	reg := t.TempDir()
	if err := Save(reg, testCredential(t)); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := Load(reg); err != nil {
		t.Fatalf("positive control: regular credential refused")
	}

	// Exact boundary: limit bytes still load.
	at := t.TempDir()
	if err := Save(at, testCredential(t)); err != nil {
		t.Fatalf("save: %v", err)
	}
	padKeyFile(t, at, limit)
	if _, err := Load(at); err != nil {
		t.Fatalf("file of exactly %d bytes must load", limit)
	}

	// limit+1 and a long tail: refused, even though the prefix is a valid key.
	for _, size := range []int{limit + 1, limit + 4096} {
		over := t.TempDir()
		cred := testCredential(t)
		if err := Save(over, cred); err != nil {
			t.Fatalf("save: %v", err)
		}
		padKeyFile(t, over, size)
		_, err := Load(over)
		if err == nil {
			t.Fatalf("oversized key file (%d bytes) accepted by Load", size)
		}
		if !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("size %d: refusal is not the size refusal", size)
		}
		msg := err.Error()
		if c := canary.Of(string(cred.Key)); c.In(msg) {
			t.Errorf("size %d: error leaked key material", size)
		}
		// The file itself is PEM text; the raw key sits in base64 at an
		// offset the canary cannot see, so check the PEM's own pieces.
		pemBytes, rerr := os.ReadFile(filepath.Join(over, keyFileName)) //nolint:gosec // G304: test temp dir
		if rerr != nil {
			t.Fatalf("read key file: %v", rerr)
		}
		if strings.Contains(msg, "-----BEGIN") {
			t.Errorf("size %d: error carries PEM header", size)
		}
		for _, line := range strings.Split(string(pemBytes), "\n") {
			if len(line) >= 16 && !strings.HasPrefix(line, "-----") && strings.Contains(msg, line[:16]) {
				t.Errorf("size %d: error carries PEM body", size)
			}
		}
		for _, n := range []int{size, limit + 1, limit} {
			if strings.Contains(msg, strconv.Itoa(n)) {
				t.Errorf("size %d: error carries a file size", size)
			}
		}
	}

	// Invalid PEM stays refused (unchanged behaviour).
	bad := t.TempDir()
	if err := Save(bad, testCredential(t)); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bad, keyFileName), []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(bad); err == nil {
		t.Fatal("invalid PEM accepted")
	}
}
