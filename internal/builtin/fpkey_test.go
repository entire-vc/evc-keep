package builtin

import (
	"context"
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
)

// TestFingerprintKey_StableAcrossReopen checks that the fingerprint key
// survives a restart: a fresh Provider (and a fresh Sealer, over the same
// root key and pool — standing in for a server restart, which keeps the
// root key but rebuilds everything else) must unseal the exact same
// fingerprint key, not generate a new one — checked by comparing what both
// compute for the same value, since the key's own bytes are never readable
// outside the plaintext zone.
func TestFingerprintKey_StableAcrossReopen(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	rootBytes := make([]byte, 32)
	rootBytes[0] = 1
	root, err := sealer.NewLocalRootKey("root-fp-test", rootBytes)
	if err != nil {
		t.Fatal(err)
	}
	scope := sealer.Scope{Org: randID(t, "org"), User: "alice"}

	s1 := sealer.New(root, &recAudit{}, newStore(pool))
	p1 := New(pool, s1, scope, nil)
	k1, err := p1.FingerprintKey(ctx)
	if err != nil {
		t.Fatalf("first FingerprintKey: %v", err)
	}

	// A fresh Sealer + Provider, same root key and pool: the "restart".
	s2 := sealer.New(root, &recAudit{}, newStore(pool))
	p2 := New(pool, s2, scope, nil)
	k2, err := p2.FingerprintKey(ctx)
	if err != nil {
		t.Fatalf("second FingerprintKey: %v", err)
	}

	if k1.ID() != k2.ID() {
		t.Fatalf("fingerprint key id changed across reopen: %s vs %s", k1.ID(), k2.ID())
	}
	v := secretOf("some-value-to-fingerprint")
	f1, err := fingerprint.Compute(k1, v)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := fingerprint.Compute(k2, v)
	if err != nil {
		t.Fatal(err)
	}
	if f1 != f2 {
		t.Fatalf("fingerprints differ across reopen: %s vs %s — the underlying key bytes changed", f1, f2)
	}
}

// TestFingerprintKey_ConcurrentFirstCall proves the race in FingerprintKey's
// insertIfAbsent fallback actually converges: many concurrent first calls
// for a brand-new store must all end up agreeing on one key.
func TestFingerprintKey_ConcurrentFirstCall(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	scope := sealer.Scope{Org: randID(t, "org"), User: "alice"}
	p := New(pool, seal, scope, nil)

	const n = 8
	ids := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			k, err := p.FingerprintKey(ctx)
			if err == nil {
				ids[i] = k.ID()
			}
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("FingerprintKey[%d]: %v", i, err)
		}
	}
	winner := ids[0]
	for i, id := range ids {
		if id != winner {
			t.Fatalf("FingerprintKey[%d] id %q, want the same winner %q for every concurrent first caller", i, id, winner)
		}
	}
}

// TestFingerprintKey_DistinctPerStore is the store-isolation half of §4.1's
// guard (a): two different stores must not end up with the same
// fingerprint key, or a tag from one would look meaningful compared against
// the other's catalog.
func TestFingerprintKey_DistinctPerStore(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	org := randID(t, "org")
	pa := New(pool, seal, sealer.Scope{Org: org, User: "alice"}, nil)
	pb := New(pool, seal, sealer.Scope{Org: org, User: "bob"}, nil)

	ka, err := pa.FingerprintKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := pb.FingerprintKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ka.ID() == kb.ID() {
		t.Fatalf("alice and bob share a fingerprint key id %s", ka.ID())
	}
	v := secretOf("shared-value")
	fa, err := fingerprint.Compute(ka, v)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := fingerprint.Compute(kb, v)
	if err != nil {
		t.Fatal(err)
	}
	if fa == fb {
		t.Fatal("the same value fingerprints identically under two different stores' keys")
	}
}

// TestFingerprintKey_NoCanaryInError provokes the FingerprintKey path with a
// canary present in the store (a real secret written alongside it) and
// checks the key material itself never appears in an error string.
func TestFingerprintKey_NoCanaryInError(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	scope := sealer.Scope{Org: randID(t, "org"), User: "alice"}
	p := New(pool, seal, scope, nil)
	c := canary.New()

	if _, err := p.Write(ctx, providerRef("s1"), secretOf(c.Value(1))); err != nil {
		t.Fatalf("Write: %v", err)
	}
	k, err := p.FingerprintKey(ctx)
	if err != nil {
		t.Fatalf("FingerprintKey: %v", err)
	}
	tag, err := fingerprint.Compute(k, secretOf(c.Value(1)))
	if err != nil {
		t.Fatal(err)
	}
	if c.In(tag) {
		t.Fatalf("fingerprint tag contains the canary: %s", tag)
	}

	// Provoke openFingerprintKey's actual error path: corrupt the persisted
	// wrapped key so unwrapping fails (sealer.ErrUnwrap), then read the key
	// back again and check the raw key bytes (not the canary — there is no
	// value here, only key material) never surface in the error text.
	if _, err := pool.Exec(ctx, `UPDATE keep_envelope SET wrapped_dek = wrapped_dek || 'x'::bytea
		WHERE store_org = $1 AND store_user = $2 AND secret_id = $3`, scope.Org, scope.User, fpKeySecretID); err != nil {
		t.Fatalf("corrupt wrapped fingerprint key: %v", err)
	}
	_, err = p.FingerprintKey(ctx)
	if err == nil {
		t.Fatal("FingerprintKey succeeded after its wrapped key was corrupted — the corruption did not take, this test proves nothing")
	}
	rawKeyHex := hex.EncodeToString(rawKeyBytes(t, k))
	if strings.Contains(err.Error(), rawKeyHex) {
		t.Fatalf("fingerprint key bytes leaked into FingerprintKey's error: %v", err)
	}
}

// rawKeyBytes exposes k's bytes for this test's own comparison — legal
// here: internal/builtin is in the plaintext zone, and this is a _test.go
// file of the package that owns fingerprint.ExposeKey's call site.
func rawKeyBytes(t *testing.T, k fingerprint.Key) []byte {
	t.Helper()
	var b []byte
	fingerprint.ExposeKey(k, func(raw []byte) { b = append([]byte(nil), raw...) })
	return b
}
