package builtin

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func TestKEKStore_ActiveFor_MissingIsErrNoActiveKEK(t *testing.T) {
	pool := testPool(t)
	s := newStore(pool)
	org := randID(t, "org")
	if _, err := s.ActiveFor(context.Background(), org, "domain/x"); !errors.Is(err, sealer.ErrNoActiveKEK) {
		t.Fatalf("err = %v, want ErrNoActiveKEK", err)
	}
}

func TestKEKStore_CreateThenActiveFor_RoundTrips(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	s := newStore(pool)
	org := randID(t, "org")
	want := sealer.KEKRecord{
		ID:        randID(t, "kek"),
		Org:       org,
		Domain:    sealer.Scope{Org: org, User: "alice"},
		RootKeyID: "root-1",
		Wrapped:   []byte("wrapped-bytes-not-a-real-key"),
	}
	got, err := s.Create(ctx, "domain/alice", want)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got.ID != want.ID || got.Org != want.Org || got.Domain != want.Domain || got.RootKeyID != want.RootKeyID || string(got.Wrapped) != string(want.Wrapped) {
		t.Fatalf("Create returned %+v, want %+v", got, want)
	}

	active, err := s.ActiveFor(ctx, org, "domain/alice")
	if err != nil {
		t.Fatalf("ActiveFor: %v", err)
	}
	if active.ID != want.ID {
		t.Fatalf("ActiveFor.ID = %q, want %q", active.ID, want.ID)
	}

	fetched, err := s.Get(ctx, org, want.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if fetched.ID != want.ID {
		t.Fatalf("Get.ID = %q, want %q", fetched.ID, want.ID)
	}
}

// Create must behave as an atomic get-or-create: of many concurrent callers
// racing to create the active KEK of the same domain, exactly one record
// wins and every caller observes that same one — this is what lets
// Sealer.activeKEK skip a lock around the whole operation and still be
// correct under concurrent Seal calls from multiple server processes.
func TestKEKStore_Create_ConcurrentCallersConverge(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	s := newStore(pool)
	org := randID(t, "org")
	domainKey := "domain/race"

	const n = 12
	results := make([]sealer.KEKRecord, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			want := sealer.KEKRecord{
				ID:        randID(t, "kek"),
				Org:       org,
				Domain:    sealer.Scope{Org: org, User: "race"},
				RootKeyID: "root-1",
				Wrapped:   []byte("wrapped-" + randID(t, "")),
			}
			results[i], errs[i] = s.Create(ctx, domainKey, want)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Create[%d]: %v", i, err)
		}
	}
	winner := results[0].ID
	for i, r := range results {
		if r.ID != winner {
			t.Fatalf("Create[%d].ID = %q, want the same winner %q for every concurrent caller", i, r.ID, winner)
		}
	}

	list, err := s.ActiveList(ctx, org)
	if err != nil {
		t.Fatalf("ActiveList: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ActiveList returned %d records for one domain, want exactly 1 (the race produced more than one active KEK)", len(list))
	}
}

// Get must never resolve a KEK id under the wrong org: a leaked or guessed
// id from one organisation must not unwrap another's DEKs (tenancy model
// §5, threat model C6). This is what scripts/check-builtin-mutations.sh's
// get-crosses-org mutation proves can fail — the equivalent check used to
// live in internal/builtin/sealer against an in-memory map (see that
// package's mutation script history) and moved here with the map.
func TestGet_DoesNotCrossOrgBoundary(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	s := newStore(pool)
	orgA, orgB := randID(t, "org"), randID(t, "org")

	rec := sealer.KEKRecord{
		ID:        randID(t, "kek"),
		Org:       orgA,
		Domain:    sealer.Scope{Org: orgA, User: "alice"},
		RootKeyID: "root-1",
		Wrapped:   []byte("wrapped-bytes"),
	}
	if _, err := s.Create(ctx, "domain/alice", rec); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := s.Get(ctx, orgB, rec.ID); err == nil {
		t.Fatal("Get resolved orgA's KEK id when asked for it under orgB")
	}
	if _, err := s.Get(ctx, orgA, rec.ID); err != nil {
		t.Fatalf("Get(correct org) failed: %v", err)
	}
}

func TestKEKStore_Retire_RemovesFromActiveKeepsGettable(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	s := newStore(pool)
	org := randID(t, "org")
	rec := sealer.KEKRecord{ID: randID(t, "kek"), Org: org, Domain: sealer.Scope{Org: org, User: "alice"}, RootKeyID: "root-1", Wrapped: []byte("w")}
	if _, err := s.Create(ctx, "domain/alice", rec); err != nil {
		t.Fatal(err)
	}
	if err := s.Retire(ctx, org, []string{rec.ID}); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if _, err := s.ActiveFor(ctx, org, "domain/alice"); !errors.Is(err, sealer.ErrNoActiveKEK) {
		t.Fatalf("ActiveFor after retire: err = %v, want ErrNoActiveKEK", err)
	}
	if _, err := s.Get(ctx, org, rec.ID); err != nil {
		t.Fatalf("Get after retire (must stay readable until Purge): %v", err)
	}
	retired, err := s.RetiredList(ctx, org)
	if err != nil || len(retired) != 1 || retired[0].ID != rec.ID {
		t.Fatalf("RetiredList = %+v, err %v, want [%s]", retired, err, rec.ID)
	}
	// Retiring an already-retired id is a no-op, not an error.
	if err := s.Retire(ctx, org, []string{rec.ID}); err != nil {
		t.Fatalf("Retire (idempotent): %v", err)
	}
}

func TestKEKStore_Purge_DeletesRetiredKeepsActive(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	s := newStore(pool)
	org := randID(t, "org")
	active := sealer.KEKRecord{ID: randID(t, "kek"), Org: org, Domain: sealer.Scope{Org: org, User: "alice"}, RootKeyID: "root-1", Wrapped: []byte("w")}
	retired := sealer.KEKRecord{ID: randID(t, "kek"), Org: org, Domain: sealer.Scope{Org: org, User: "bob"}, RootKeyID: "root-1", Wrapped: []byte("w")}
	if _, err := s.Create(ctx, "domain/alice", active); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(ctx, "domain/bob", retired); err != nil {
		t.Fatal(err)
	}
	if err := s.Retire(ctx, org, []string{retired.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.Purge(ctx, org, []string{retired.ID}); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if _, err := s.Get(ctx, org, retired.ID); err == nil {
		t.Fatal("purged KEK is still Get-able")
	}
	if _, err := s.Get(ctx, org, active.ID); err != nil {
		t.Fatalf("Purge touched the still-active KEK: %v", err)
	}
}

// TestKEKStore_Purge_RefusesAStillActiveID closes a gap
// TestKEKStore_Purge_DeletesRetiredKeepsActive above leaves open: that test
// never actually asks Purge to delete an active id, so it could not have
// caught Purge deleting one if asked — this does ask, directly, and requires
// the state='retired' guard in the query to hold even though the id is
// explicitly on the purge list (Sealer.Purge itself would never pass an
// active id — this is the store-level guard behind that assumption).
func TestKEKStore_Purge_RefusesAStillActiveID(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	s := newStore(pool)
	org := randID(t, "org")
	active := sealer.KEKRecord{ID: randID(t, "kek"), Org: org, Domain: sealer.Scope{Org: org, User: "alice"}, RootKeyID: "root-1", Wrapped: []byte("w")}
	if _, err := s.Create(ctx, "domain/alice", active); err != nil {
		t.Fatal(err)
	}
	if err := s.Purge(ctx, org, []string{active.ID}); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if _, err := s.Get(ctx, org, active.ID); err != nil {
		t.Fatalf("Purge deleted a still-active KEK just because its id was on the list: %v", err)
	}
}

// TestKEKStore_Retire_DoesNotCrossOrgBoundary and
// TestKEKStore_Purge_DoesNotCrossOrgBoundary close another gap: Retire/Purge
// take an org parameter that TestKEKStore_Retire_RemovesFromActiveKeepsGettable
// and TestKEKStore_Purge_DeletesRetiredKeepsActive never actually exercised
// with a wrong org — both passed the KEK's own correct org every time, so
// neither could have caught the WHERE clause's org_id filter going missing.
func TestKEKStore_Retire_DoesNotCrossOrgBoundary(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	s := newStore(pool)
	orgA, orgB := randID(t, "org"), randID(t, "org")
	rec := sealer.KEKRecord{ID: randID(t, "kek"), Org: orgA, Domain: sealer.Scope{Org: orgA, User: "alice"}, RootKeyID: "root-1", Wrapped: []byte("w")}
	if _, err := s.Create(ctx, "domain/alice", rec); err != nil {
		t.Fatal(err)
	}
	if err := s.Retire(ctx, orgB, []string{rec.ID}); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if _, err := s.ActiveFor(ctx, orgA, "domain/alice"); err != nil {
		t.Fatalf("orgA's KEK was retired by a Retire call scoped to orgB: %v", err)
	}
}

func TestKEKStore_Purge_DoesNotCrossOrgBoundary(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	s := newStore(pool)
	orgA, orgB := randID(t, "org"), randID(t, "org")
	rec := sealer.KEKRecord{ID: randID(t, "kek"), Org: orgA, Domain: sealer.Scope{Org: orgA, User: "alice"}, RootKeyID: "root-1", Wrapped: []byte("w")}
	if _, err := s.Create(ctx, "domain/alice", rec); err != nil {
		t.Fatal(err)
	}
	if err := s.Retire(ctx, orgA, []string{rec.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.Purge(ctx, orgB, []string{rec.ID}); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if _, err := s.Get(ctx, orgA, rec.ID); err != nil {
		t.Fatalf("orgA's retired KEK was purged by a Purge call scoped to orgB: %v", err)
	}
}

// TestNoCanaryInDatabase drives a full Write / Resolve / ChangeLevel /
// Disable / Erase cycle with a canary value and then scans every text and
// bytea column of every public.keep_* table directly,
// in the same six encodings pkg/provider/providertest and
// internal/testutil/canary check: no column may carry the value in the
// clear.
func TestNoCanaryInDatabase(t *testing.T) {
	ctx := context.Background()
	pool := databaseSecurityPool(t)
	seal, _ := testSealer(t, pool)
	org := randID(t, "org")
	scope := sealer.Scope{Org: org, User: "alice"}
	p := New(pool, seal, scope, nil)
	admin := NewAdmin(pool, seal, org, nil)
	c := canary.New()

	meta, err := p.Write(ctx, providerRef("s1"), secretOf(c.Value(1)))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := p.Write(ctx, providerRef("s1"), secretOf(c.Value(2))); err != nil {
		t.Fatalf("Write v2: %v", err)
	}
	if _, err := admin.ChangeLevel(ctx, sealer.LevelOrg, "admin-"+randID(t, ""), true); err != nil {
		t.Fatalf("ChangeLevel: %v", err)
	}
	if err := p.Disable(ctx, providerRefVersion("s1", meta.Version)); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if err := p.Erase(ctx, providerRefVersion("s1", meta.Version)); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if _, err := p.FingerprintKey(ctx); err != nil {
		t.Fatalf("FingerprintKey: %v", err)
	}

	columns := databaseSecurityColumns(t, pool)
	found := databaseMatches(t, pool, columns, func(b []byte) bool {
		return c.In(string(b)) || c.In(hex.EncodeToString(b))
	})
	if len(found) != 0 {
		t.Fatalf("canary found in %s.%s", found[0].table, found[0].name)
	}
}

// TestWrappedDEKIsActuallyWrapped guards against a value ending up stored as
// an unwrapped DEK rather than one properly sealed under the store's KEK
// (see scripts/check-builtin-mutations.sh's dek-stored-unwrapped). A DEK is
// a random 32-byte AES-256 key; sealed under a KEK with AES-256-GCM it is
// always exactly 32 + 12 (nonce) + 16 (tag) = 60 bytes, never 32 — so a
// plain length check already catches the unwrapped case, and the second
// half of this test rules out something subtler that still happens to land
// on 60 bytes: the stored bytes must not themselves open the value's
// ciphertext, under the value's real AAD, when used directly as a raw
// AES-256-GCM key. valueAADForTest reimplements sealer's unexported
// valueAAD independently rather than importing it, so this check does not
// depend on, or trust, the production code's own AAD builder.
func TestWrappedDEKIsActuallyWrapped(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	scope := sealer.Scope{Org: randID(t, "org"), User: "alice"}
	p := New(pool, seal, scope, nil)

	if _, err := p.Write(ctx, providerRef("s1"), secretOf("value")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	row, err := p.db.byVersion(ctx, scope, "s1", 1)
	if err != nil {
		t.Fatal(err)
	}

	const dekLen, gcmOverhead = 32, 12 + 16
	if len(row.wrapped) != dekLen+gcmOverhead {
		t.Fatalf("wrapped_dek length = %d, want exactly %d (a %d-byte DEK sealed with AES-256-GCM)", len(row.wrapped), dekLen+gcmOverhead, dekLen)
	}

	block, err := aes.NewCipher(row.wrapped[:dekLen])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	if len(row.cipher) < gcm.NonceSize() {
		t.Fatalf("ciphertext too short to carry a nonce: %d bytes", len(row.cipher))
	}
	// Write's version is the secret's own path ("s1") as both id and name,
	// version "1" for a first write — see provider.go's Write.
	valueAAD := valueAADForTest(scope.Org, "s1", "s1", "1")
	if _, err := gcm.Open(nil, row.cipher[:gcm.NonceSize()], row.cipher[gcm.NonceSize():], valueAAD); err == nil {
		t.Fatal("value ciphertext opened directly with the first 32 bytes of wrapped_dek as a raw key — the DEK was stored unwrapped")
	}
}

// TestRewrap_DoesNotResurrectConcurrentlyErasedRow closes the window between
// Rewrap's own batch SELECT and its per-row UPDATE: Rewrap reads every row
// with a wrapped DEK up front, then calls fn and persists what it returns
// one row at a time. If a version is erased after the SELECT already read
// it but before its UPDATE runs, the UPDATE used to name only the primary
// key — it would happily write fn's freshly re-wrapped result (computed
// from the row's pre-erase envelope) straight over the NULLs erase had just
// set, undoing a crypto-erasure that is supposed to be permanent. The fix
// is the "AND status <> 'erased'" guard on that UPDATE; this test drives fn
// to pause exactly in that window, erases the row from a concurrent call,
// then requires the row to stay erased.
func TestRewrap_DoesNotResurrectConcurrentlyErasedRow(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	org := randID(t, "org")
	scope := sealer.Scope{Org: org, User: "alice"}
	p := New(pool, seal, scope, nil)

	if _, err := p.Write(ctx, providerRef("s"), secretOf("v1")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	pausedInFn := make(chan struct{})
	resume := make(chan struct{})
	fn := func(ref sealer.Ref, e sealer.Envelope) (sealer.Envelope, error) {
		close(pausedInFn)
		<-resume
		// Stands in for whatever a real re-wrap would compute from the
		// row's pre-erase envelope — the point is that Rewrap's UPDATE must
		// refuse to apply this once the row is erased, not that this value
		// itself looks like a real KEK/DEK.
		return sealer.Envelope{KEKID: "attacker-kek", WrappedDEK: []byte("resurrected-dek-bytes-000000000"), Ciphertext: e.Ciphertext}, nil
	}

	rewrapErr := make(chan error, 1)
	go func() { rewrapErr <- p.db.Rewrap(ctx, org, fn) }()

	select {
	case <-pausedInFn:
	case <-time.After(5 * time.Second):
		t.Fatal("Rewrap did not call fn in time")
	}

	if err := p.Erase(ctx, providerRefVersion("s", "1")); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	close(resume)
	if err := <-rewrapErr; err != nil {
		t.Fatalf("Rewrap: %v", err)
	}

	got, err := p.db.byVersion(ctx, scope, "s", 1)
	if err != nil {
		t.Fatal(err)
	}
	if got.status != "erased" || got.kekID != "" || got.wrapped != nil {
		t.Fatalf("erased row was resurrected by a concurrent Rewrap: status=%q kek_id=%q wrapped_dek=%v", got.status, got.kekID, got.wrapped)
	}
}

// TestDisable_DoesNotOverwriteErasedVersion closes a second, independent
// path to the resurrection TestRewrap_DoesNotResurrectConcurrentlyErasedRow
// guards against: a Disable that decided a row was 'active' must not
// overwrite a concurrent Erase's 'erased' back to 'disabled' — Rewrap's own
// guard checks status <> 'erased', which 'disabled' satisfies. The disable
// UPDATE only ever moves a row away from 'active', so a stale read cannot
// resurrect an erased row: disabling an already-erased version (the
// stale-read case) must be a no-op that leaves the erasure intact.
func TestDisable_DoesNotOverwriteErasedVersion(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	scope := sealer.Scope{Org: randID(t, "org"), User: "alice"}
	p := New(pool, seal, scope, nil)

	if _, err := p.Write(ctx, providerRef("s"), secretOf("v1")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := p.Erase(ctx, providerRefVersion("s", "1")); err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if err := p.Disable(ctx, providerRefVersion("s", "1")); err != nil {
		t.Fatalf("Disable(erased) = %v, want idempotent nil", err)
	}

	got, err := p.db.byVersion(ctx, scope, "s", 1)
	if err != nil {
		t.Fatal(err)
	}
	if got.status != "erased" || got.kekID != "" || got.wrapped != nil {
		t.Fatalf("Disable overwrote an erased row: status=%q kek_id=%q wrapped_dek=%v", got.status, got.kekID, got.wrapped)
	}
}

// TestDisable_DoesNotOverwriteConcurrentErase: Erase takes no secret lock, so
// it can land between Disable's status read and its UPDATE. The UPDATE's own
// status = 'active' guard must then make Disable a no-op instead of turning
// the erased row back into 'disabled'. An uncommitted erase held open by the
// test makes that interleaving deterministic.
func TestDisable_DoesNotOverwriteConcurrentErase(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	scope := sealer.Scope{Org: randID(t, "org"), User: "alice"}
	p := New(pool, seal, scope, nil)

	for _, v := range []string{"v1", "v2"} {
		if _, err := p.Write(ctx, providerRef("s"), secretOf(v)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	erase, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = erase.Rollback(ctx) }()
	if _, err := erase.Exec(ctx, `UPDATE keep_envelope SET wrapped_dek = NULL, kek_id = NULL, status = 'erased'
		WHERE store_org = $1 AND secret_id = 's' AND version = 1`, scope.Org); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- p.Disable(ctx, providerRefVersion("s", "1")) }()

	// Disable has read status = 'active' and now waits on the erase's row lock.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
			WHERE wait_event_type = 'Lock' AND query LIKE 'UPDATE keep_envelope SET status = ''disabled''%'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Disable never reached its UPDATE")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := erase.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Disable = %v, want idempotent nil", err)
	}

	got, err := p.db.byVersion(ctx, scope, "s", 1)
	if err != nil {
		t.Fatal(err)
	}
	if got.status != "erased" {
		t.Fatalf("Disable overwrote a concurrently erased row: status=%q", got.status)
	}
}
