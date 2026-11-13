package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func runTransfer(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := offlineTransfer(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func carrierDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "c")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestTransferRecipientKeepsThePrivateKeyInItsCarrier(t *testing.T) {
	d := carrierDir(t)
	priv, pub := filepath.Join(d, "recipient.key"), filepath.Join(d, "recipient.pub")
	code, out, errs := runTransfer("recipient", "--private-file", priv, "--public-file", pub)
	if code != 0 {
		t.Fatalf("positive control failed: %d %s", code, errs)
	}
	key, err := os.ReadFile(priv) //nolint:gosec // G304: test path
	if err != nil || len(key) == 0 {
		t.Fatal("private carrier missing")
	}
	pb, err := os.ReadFile(pub) //nolint:gosec // G304: test path
	if err != nil || bytes.Equal(key, pb) {
		t.Fatal("public carrier missing or equals the private key")
	}
	if fi, _ := os.Stat(priv); fi.Mode().Perm() != 0o600 {
		t.Fatal("private carrier is not 0600")
	}
	// Positive control for the canary: the key really is what we search for.
	c := canary.Of(string(key))
	if !c.In(string(key)) {
		t.Fatal("canary does not see the key in its own text")
	}
	if c.In(out) || c.In(errs) {
		t.Fatal("private key reached stdout or stderr")
	}
	sum := sha256.Sum256(pb)
	if !strings.Contains(out, "recipient_fingerprint="+hex.EncodeToString(sum[:])) {
		t.Fatalf("receipt lacks the public fingerprint: %q", out)
	}
	if strings.Contains(out, d) || strings.Contains(errs, d) {
		t.Fatal("receipt reflects a path")
	}
}

func TestTransferRecipientRefusalsCreateNothingAndLeakNothing(t *testing.T) {
	d := carrierDir(t)
	existing := filepath.Join(d, "taken")
	if err := os.WriteFile(existing, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	priv, pub := filepath.Join(d, "k"), filepath.Join(d, "p")

	// Private path taken: nothing is created.
	code, out, errs := runTransfer("recipient", "--private-file", existing, "--public-file", pub)
	if code != 1 || !strings.Contains(errs, "reason=carrier_exists") || out != "" {
		t.Fatalf("existing private path: %d %q %q", code, out, errs)
	}
	if _, err := os.Lstat(pub); err == nil {
		t.Fatal("public carrier created after a refusal")
	}
	// Public path taken: the private key written a moment earlier is removed.
	code, _, errs = runTransfer("recipient", "--private-file", priv, "--public-file", existing)
	if code != 1 || !strings.Contains(errs, "reason=carrier_exists") {
		t.Fatalf("existing public path: %d %q", code, errs)
	}
	if _, err := os.Lstat(priv); err == nil {
		t.Fatal("private key left behind without its public half")
	}
	if b, _ := os.ReadFile(existing); string(b) != "original" { //nolint:gosec // G304: test path
		t.Fatal("an existing file was changed")
	}
	for name, args := range map[string][]string{
		"no args":        {},
		"unknown":        {"nonsense"},
		"missing flag":   {"recipient", "--private-file", priv},
		"same path":      {"recipient", "--private-file", priv, "--public-file", priv},
		"extra argument": {"recipient", "--private-file", priv, "--public-file", pub, "x"},
		"unknown flag":   {"recipient", "--private-file", priv, "--public-file", pub, "--dsn", "postgres://leak-me"},
	} {
		code, out, errs := runTransfer(args...)
		if code != 2 || out != "" || strings.Contains(errs, "leak-me") || strings.Contains(errs, d) {
			t.Errorf("%s: %d %q %q", name, code, out, errs)
		}
	}
}
