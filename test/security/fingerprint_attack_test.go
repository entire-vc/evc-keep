// Attacks against pkg/fingerprint (contract R-CAR-3, threat model §4.1),
// independent of fingerprint_test.go.
package security

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

func mustKey(t *testing.T, id string) fingerprint.Key {
	t.Helper()
	k, err := fingerprint.GenerateKey(id)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestFingerprint_SameValueDifferentTenantsDiffer independently re-derives
// the tenant-separation guard: two DIFFERENT stores (which per R-CAR-3
// always carry their own fp_key) must never produce the same fingerprint
// TAG for the same underlying value — otherwise an attacker who
// compromises one tenant's fp_key could recognise (not read, but
// recognise) a value shared with another tenant. The comparison is on the
// tag (the HMAC output) alone, not the full "kfp1:<key_id>:<tag>" string:
// the key_id segment is a public store label chosen independently of the
// HMAC key material, so comparing full strings would pass even if the
// underlying key were NOT actually bound to the store (caught by
// a mutation run: a fixed-HMAC-key mutation left the full-string comparison
// green because storea/storeb still produced different key_id prefixes).
func TestFingerprint_SameValueDifferentTenantsDiffer(t *testing.T) {
	kA := mustKey(t, "storea")
	kB := mustKey(t, "storeb")
	v := secret.New([]byte("shared-password-123"))

	fpA, err := fingerprint.Compute(kA, v)
	if err != nil {
		t.Fatal(err)
	}
	fpB, err := fingerprint.Compute(kB, v)
	if err != nil {
		t.Fatal(err)
	}
	tagA := strings.SplitN(fpA, ":", 3)[2]
	tagB := strings.SplitN(fpB, ":", 3)[2]
	if tagA == tagB {
		t.Fatalf("identical value under two different stores' keys produced the SAME fingerprint tag: %s", tagA)
	}
}

// TestFingerprint_NotABareHashUnderAnyTruncation independently re-derives
// the "no bare hash anywhere" guard — the sha256[:8]-is-not-a-fingerprint
// rule the contract calls out by name — across every truncation length a
// careless reimplementation might pick, not just the one the developer's
// own test happened to check.
func TestFingerprint_NotABareHashUnderAnyTruncation(t *testing.T) {
	// The raw bytes are known here because THIS test chose them, before
	// they were ever wrapped in a secret.Value — not obtained via
	// secret.Expose, which is off-limits outside the plaintext zone
	// (.golangci.yml "expose-callers": pkg/fingerprint, pkg/provider,
	// internal/builtin, internal/runner, internal/targets only).
	raw := []byte("some-secret-value")
	v := secret.New(raw)
	sum := sha256.Sum256(raw)
	hexSum := hex.EncodeToString(sum[:])

	k := mustKey(t, "store1")
	fp, err := fingerprint.Compute(k, v)
	if err != nil {
		t.Fatal(err)
	}
	tag := strings.SplitN(fp, ":", 3)[2]

	for n := 4; n <= len(hexSum); n++ {
		if strings.EqualFold(tag, hexSum[:n]) {
			t.Fatalf("fingerprint tag matches sha256(value) truncated to %d hex chars", n)
		}
	}
}

// TestFingerprint_PINBruteForceRequiresTheKey proves that brute-forcing a
// captured fingerprint against all 10^6 six-digit PINs succeeds ONLY for
// whoever holds the store's fp_key — i.e. the fingerprint format itself
// adds no weakness beyond ordinary low-entropy-secret risk, and the entire
// defense is fp_key confidentiality (which the KEK/envelope layer already
// protects at the same strength as the secret's own value — tested in
// sealer_attack_test.go).
func TestFingerprint_PINBruteForceRequiresTheKey(t *testing.T) {
	realKey := mustKey(t, "store1")
	pin := secret.New([]byte("204817")) // the "victim" PIN
	target, err := fingerprint.Compute(realKey, pin)
	if err != nil {
		t.Fatal(err)
	}

	// Attacker WITHOUT the key: the only exported way to test a guess is
	// fingerprint.Compute, which requires an actual fingerprint.Key value —
	// constructible only via NewKey/GenerateKey, both of which demand 32
	// real bytes of key material. There is no exported function that
	// computes or compares a fingerprint without one. An attacker who only
	// has the captured fingerprint string cannot even START a brute force.
	if _, err := fingerprint.NewKey("attacker", make([]byte, 32)); err == nil {
		t.Fatal("NewKey accepted an all-zero key — this would let an attacker brute-force with a known/guessable key")
	}

	// Attacker who guesses/steals a WRONG key: brute-forcing under the
	// wrong key must never collide with target. A sample of 50k guesses
	// (not the full 10^6 space — that cost buys nothing extra here: HMAC
	// output is keyed per-store, so a collision under the wrong key would
	// mean a break in the HMAC itself, and 50k independent samples already
	// catch a key-independence bug like "Compute ignores the key" just as
	// reliably as 10^6 would, at a fraction of the -race runtime).
	wrongKey := mustKey(t, "store2")
	found := false
	for i := 0; i < 50_000; i++ {
		guess := secret.New([]byte(fmt.Sprintf("%06d", i)))
		fp, err := fingerprint.Compute(wrongKey, guess)
		if err != nil {
			t.Fatal(err)
		}
		if fp == target {
			found = true
			break
		}
	}
	if found {
		t.Fatal("a PIN brute force under the WRONG key matched the target fingerprint — fingerprint collision or a key-independence bug")
	}

	// Documented, not asserted-safe: an attacker who DOES hold the real
	// key can brute-force the full 6-digit PIN space in well under a
	// second — this is the honest boundary the contract draws (without the
	// key, brute force is pointless): fp_key confidentiality is the WHOLE defense
	// for a low-entropy secret, not a property of the fingerprint
	// algorithm. It is logged here, not failed, because it is not a
	// fingerprint-package defect — whoever holds fp_key already holds
	// enough to unwrap the DEK and read the plaintext directly (§4.6), so
	// this adds no capability beyond what KEK compromise already grants.
	start := time.Now()
	matched := -1
	for i := 0; i < 1_000_000; i++ {
		guess := secret.New([]byte(fmt.Sprintf("%06d", i)))
		fp, err := fingerprint.Compute(realKey, guess)
		if err != nil {
			t.Fatal(err)
		}
		if fp == target {
			matched = i
			break
		}
	}
	elapsed := time.Since(start)
	if matched != 204817 {
		t.Fatalf("brute force under the REAL key did not recover the known PIN (got %d) — Compute may not be deterministic", matched)
	}
	t.Logf("with the real fp_key in hand, all 10^6 six-digit PINs were tried in %s — "+
		"the fingerprint format adds no resistance to a low-entropy secret; the entire "+
		"defense is fp_key confidentiality, which is exactly what the contract claims", elapsed)
}

// TestFingerprint_ParseNeverEchoesInput independently re-checks that a
// malformed fingerprint string is never echoed back in Parse's error, in
// several shapes the developer's own malformed-input test may not have
// tried (embedded control characters, very long input, wrong key-id
// charset).
func TestFingerprint_ParseNeverEchoesInput(t *testing.T) {
	bad := []string{
		"kfp1:UPPER:aaaaaaaaaaaaaaaa",     // key id must be lowercase
		"kfp1:x:aaaaaaaaaaaaaaaa\x00\x01", // control bytes
		"kfp1:" + strings.Repeat("a", 999) + ":aaaaaaaaaaaaaaaa",
		"not-even-close-to-the-format",
		"",
		"kfp1::",
	}
	for _, s := range bad {
		t.Run(fmt.Sprintf("%q", s), func(t *testing.T) {
			_, err := fingerprint.Parse(s)
			if err == nil {
				t.Fatalf("Parse accepted malformed input %q", s)
			}
			if strings.Contains(err.Error(), s) && s != "" {
				t.Errorf("Parse error echoed the input: %v", err)
			}
		})
	}
}

// TestFingerprint_KeyNeverFormats is the fingerprint.Key analogue of
// pkg/secret's leak tests — independent because fingerprint.Key is a
// second type with its own hand-written Format/String/MarshalJSON/LogValue
// set, not a wrapper that reuses secret.Value's.
func TestFingerprint_KeyNeverFormats(t *testing.T) {
	// The raw key bytes are known here because THIS test supplied them via
	// NewKey — not obtained via fingerprint.ExposeKey, which is off-limits
	// outside the plaintext zone (.golangci.yml "fpkey-expose").
	raw := make([]byte, fingerprint.KeySize)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	k, err := fingerprint.NewKey("store1", raw)
	if err != nil {
		t.Fatal(err)
	}
	hexRaw := hex.EncodeToString(raw)

	outputs := []string{
		fmt.Sprintf("%v", k), fmt.Sprintf("%+v", k), fmt.Sprintf("%#v", k), fmt.Sprintf("%s", k),
	}
	js, err := k.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	outputs = append(outputs, string(js))

	for i, out := range outputs {
		if strings.Contains(strings.ToLower(out), strings.ToLower(hexRaw)) {
			t.Errorf("output #%d leaked the raw key material: %q", i, out)
		}
	}
}
