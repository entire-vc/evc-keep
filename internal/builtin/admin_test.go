package builtin

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"log/slog"
	"testing"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// TestC6_UserKEKIsolation_ThenLevelRoundTrip is the AC's C6 scenario over a
// real PostgreSQL-backed Sealer: two users of one organisation get distinct
// KEKs at the default (user) level — a compromise of one's KEK does not
// help read the other's — and switching the organisation to the
// "organization" level and back re-wraps everything without touching a
// single ciphertext, decrypting correctly throughout.
func TestC6_UserKEKIsolation_ThenLevelRoundTrip(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	org := randID(t, "org")
	alice := sealer.Scope{Org: org, User: "alice"}
	bob := sealer.Scope{Org: org, User: "bob"}
	pa := New(pool, seal, alice, nil)
	pb := New(pool, seal, bob, nil)
	admin := NewAdmin(pool, seal, org, nil)
	c := canary.New()

	am, err := pa.Write(ctx, providerRef("secret"), secretOf(c.Value(1)))
	if err != nil {
		t.Fatalf("alice Write: %v", err)
	}
	bm, err := pb.Write(ctx, providerRef("secret"), secretOf(c.Value(2)))
	if err != nil {
		t.Fatalf("bob Write: %v", err)
	}

	aRow, err := pa.db.byVersion(ctx, alice, "secret", 1)
	if err != nil {
		t.Fatal(err)
	}
	bRow, err := pb.db.byVersion(ctx, bob, "secret", 1)
	if err != nil {
		t.Fatal(err)
	}
	if aRow.kekID == bRow.kekID {
		t.Fatalf("C6: alice and bob share KEK %s at the default (user) level", aRow.kekID)
	}
	aCipherBefore := append([]byte(nil), aRow.cipher...)
	bCipherBefore := append([]byte(nil), bRow.cipher...)
	// The attack must actually work against its own owner, or it proves
	// nothing about isolation — see sealer's own readsWith/c6Violations for
	// the same principle at the crypto layer; here it is enough to confirm
	// the persisted KEK ids differ, since sealer's tests already cover the
	// cryptographic half of C6 (a stolen wrapped KEK cannot open another
	// scope's DEK) — this test is the persistence half: distinct rows.

	av, avm, err := pa.Resolve(ctx, providerRefVersion("secret", am.Version))
	if err != nil || avm.Version != am.Version {
		t.Fatalf("alice Resolve: %v", err)
	}
	if !av.Equal(secretOf(c.Value(1))) {
		t.Fatal("alice's resolved value differs from what was written")
	}
	bv, _, err := pb.Resolve(ctx, providerRefVersion("secret", bm.Version))
	if err != nil || !bv.Equal(secretOf(c.Value(2))) {
		t.Fatalf("bob Resolve: %v", err)
	}

	// Weaken to organization level: shares one KEK across every store —
	// must be confirmed, and it re-wraps without changing ciphertexts.
	res, err := admin.ChangeLevel(ctx, sealer.LevelOrg, "admin", true)
	if err != nil {
		t.Fatalf("ChangeLevel down: %v", err)
	}
	if res.Rewrapped == 0 {
		t.Fatal("ChangeLevel down rewrapped nothing")
	}
	aRow2, err := pa.db.byVersion(ctx, alice, "secret", 1)
	if err != nil {
		t.Fatal(err)
	}
	bRow2, err := pb.db.byVersion(ctx, bob, "secret", 1)
	if err != nil {
		t.Fatal(err)
	}
	if aRow2.kekID != bRow2.kekID {
		t.Fatal("ChangeLevel to organization did not converge alice and bob onto one KEK")
	}
	if !bytes.Equal(aRow2.cipher, aCipherBefore) {
		t.Fatal("alice's ciphertext changed across ChangeLevel down — it must only be re-wrapped, never re-encrypted")
	}
	if !bytes.Equal(bRow2.cipher, bCipherBefore) {
		t.Fatal("bob's ciphertext changed across ChangeLevel down — it must only be re-wrapped, never re-encrypted")
	}
	av2, _, err := pa.Resolve(ctx, providerRefVersion("secret", am.Version))
	if err != nil || !av2.Equal(secretOf(c.Value(1))) {
		t.Fatalf("alice Resolve after level-down: %v", err)
	}
	bv2, _, err := pb.Resolve(ctx, providerRefVersion("secret", bm.Version))
	if err != nil || !bv2.Equal(secretOf(c.Value(2))) {
		t.Fatalf("bob Resolve after level-down: %v", err)
	}

	if n, err := admin.Purge(ctx, "admin"); err != nil || n == 0 {
		t.Fatalf("Purge after level-down: n=%d err=%v, want >0 retired per-user KEKs purged", n, err)
	}

	// Strengthen back to user level: isolation restored, still decrypts.
	res, err = admin.ChangeLevel(ctx, sealer.LevelUser, "admin", false)
	if err != nil {
		t.Fatalf("ChangeLevel up: %v", err)
	}
	if res.Rewrapped == 0 {
		t.Fatal("ChangeLevel up rewrapped nothing")
	}
	aRow3, err := pa.db.byVersion(ctx, alice, "secret", 1)
	if err != nil {
		t.Fatal(err)
	}
	bRow3, err := pb.db.byVersion(ctx, bob, "secret", 1)
	if err != nil {
		t.Fatal(err)
	}
	if aRow3.kekID == bRow3.kekID {
		t.Fatal("C6: alice and bob share a KEK again after restoring the user level")
	}
	if !bytes.Equal(aRow3.cipher, aCipherBefore) {
		t.Fatal("alice's ciphertext changed across ChangeLevel up — it must only be re-wrapped, never re-encrypted")
	}
	if !bytes.Equal(bRow3.cipher, bCipherBefore) {
		t.Fatal("bob's ciphertext changed across ChangeLevel up — it must only be re-wrapped, never re-encrypted")
	}
	av3, _, err := pa.Resolve(ctx, providerRefVersion("secret", am.Version))
	if err != nil || !av3.Equal(secretOf(c.Value(1))) {
		t.Fatalf("alice Resolve after level round trip: %v", err)
	}
	bv3, _, err := pb.Resolve(ctx, providerRefVersion("secret", bm.Version))
	if err != nil || !bv3.Equal(secretOf(c.Value(2))) {
		t.Fatalf("bob Resolve after level round trip: %v", err)
	}
}

// TestC6_DatabaseLevelAttack mounts C6's attack for real, against
// PostgreSQL: unwrap bob's KEK exactly the way the sealer would (fetched
// through store.Get, unwrapped with the root key it was actually wrapped
// under) and try to use it to open alice's wrapped DEK. Comparing KEK ids
// (as TestC6_UserKEKIsolation_ThenLevelRoundTrip above does) only proves the
// two rows disagree, not that a compromised KEK is actually useless against
// the other user's data; this proves the second part, with a positive
// control right after showing the same unwrapped bytes DO open bob's own
// DEK and value, so the attack harness itself is not just failing to work
// at all.
func TestC6_DatabaseLevelAttack(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, root, _ := testSealerWithRoot(t, pool)
	org := randID(t, "org")
	alice := sealer.Scope{Org: org, User: "alice"}
	bob := sealer.Scope{Org: org, User: "bob"}
	pa := New(pool, seal, alice, nil)
	pb := New(pool, seal, bob, nil)

	if _, err := pa.Write(ctx, providerRef("secret"), secretOf("alice-value")); err != nil {
		t.Fatalf("alice Write: %v", err)
	}
	if _, err := pb.Write(ctx, providerRef("secret"), secretOf("bob-value")); err != nil {
		t.Fatalf("bob Write: %v", err)
	}
	aRow, err := pa.db.byVersion(ctx, alice, "secret", 1)
	if err != nil {
		t.Fatal(err)
	}
	bRow, err := pb.db.byVersion(ctx, bob, "secret", 1)
	if err != nil {
		t.Fatal(err)
	}
	if aRow.kekID == bRow.kekID {
		t.Fatal("test setup: alice and bob already share a KEK at the default level")
	}

	bobRec, err := pb.db.Get(ctx, org, bRow.kekID)
	if err != nil {
		t.Fatalf("Get bob's KEK record: %v", err)
	}
	bobKEK, err := root.Unwrap(bobRec.Wrapped, kekAADForTest(bobRec.ID, bobRec.Org, scopeKeyForTest(bobRec.Domain), bobRec.RootKeyID))
	if err != nil {
		t.Fatalf("unwrap bob's KEK: %v", err)
	}
	block, err := aes.NewCipher(bobKEK)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	// The attack: bob's unwrapped KEK against alice's wrapped DEK, under
	// alice's own real dekAAD (the attacker knows every field here — ref
	// and kek_id are stored in the clear alongside the ciphertext, only key
	// material is secret).
	aliceDEKAAD := dekAADForTest(scopeKeyForTest(alice), "secret", "1", aRow.kekID)
	if len(aRow.wrapped) < gcm.NonceSize() {
		t.Fatalf("alice's wrapped_dek too short: %d bytes", len(aRow.wrapped))
	}
	if _, err := gcm.Open(nil, aRow.wrapped[:gcm.NonceSize()], aRow.wrapped[gcm.NonceSize():], aliceDEKAAD); err == nil {
		t.Fatal("C6: bob's KEK opened alice's wrapped DEK")
	}

	// Positive control: the very same unwrapped bytes must open bob's own
	// DEK and, with that DEK, bob's own value — proving the attack harness
	// itself works and the failure above is real isolation, not a mistake
	// in the attack's own construction.
	bobDEKAAD := dekAADForTest(scopeKeyForTest(bob), "secret", "1", bRow.kekID)
	if len(bRow.wrapped) < gcm.NonceSize() {
		t.Fatalf("bob's wrapped_dek too short: %d bytes", len(bRow.wrapped))
	}
	bobDEK, err := gcm.Open(nil, bRow.wrapped[:gcm.NonceSize()], bRow.wrapped[gcm.NonceSize():], bobDEKAAD)
	if err != nil {
		t.Fatalf("attack harness broken: bob's own KEK does not open bob's own wrapped DEK: %v", err)
	}
	valBlock, err := aes.NewCipher(bobDEK)
	if err != nil {
		t.Fatal(err)
	}
	valGCM, err := cipher.NewGCM(valBlock)
	if err != nil {
		t.Fatal(err)
	}
	bobValueAAD := valueAADForTest(bob.Org, "secret", "secret", "1")
	if len(bRow.cipher) < valGCM.NonceSize() {
		t.Fatalf("bob's ciphertext too short: %d bytes", len(bRow.cipher))
	}
	plain, err := valGCM.Open(nil, bRow.cipher[:valGCM.NonceSize()], bRow.cipher[valGCM.NonceSize():], bobValueAAD)
	if err != nil || string(plain) != "bob-value" {
		t.Fatalf("attack harness broken: bob's own DEK does not open bob's own value: %v", err)
	}
}

// TestChangeLevel_WeakeningWithoutConfirmation_IsRefused is the AC's red
// run #3: sharing a KEK across a whole organisation when the level is
// "user" without ConfirmWeakening must be refused, nothing re-wrapped.
func TestChangeLevel_WeakeningWithoutConfirmation_IsRefused(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	org := randID(t, "org")
	admin := NewAdmin(pool, seal, org, nil)

	_, err := admin.ChangeLevel(ctx, sealer.LevelOrg, "admin", false)
	if !errors.Is(err, sealer.ErrWeakeningNotConfirmed) {
		t.Fatalf("err = %v, want ErrWeakeningNotConfirmed", err)
	}
	level, err := seal.Level(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	if level != sealer.LevelUser {
		t.Fatalf("level changed to %v on a refused change", level)
	}
}

// TestLevel_PersistsAcrossRestart proves an organisation's key level
// survives a restart: a brand-new Sealer built over the same PostgreSQL
// pool (standing in for a restarted server process, which loses every
// in-memory value but keeps the database — the same pattern
// TestFingerprintKey_StableAcrossReopen uses) must see the level a previous
// process's ChangeLevel set, not the package default.
func TestLevel_PersistsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal1, _ := testSealer(t, pool)
	org := randID(t, "org")
	admin1 := NewAdmin(pool, seal1, org, nil)
	if _, err := admin1.ChangeLevel(ctx, sealer.LevelOrg, "admin", true); err != nil {
		t.Fatalf("ChangeLevel: %v", err)
	}

	seal2, _ := testSealer(t, pool) // a fresh Sealer, own root — only Level is exercised here
	got, err := seal2.Level(ctx, org)
	if err != nil {
		t.Fatalf("Level: %v", err)
	}
	if got != sealer.LevelOrg {
		t.Fatalf("level after restart = %v, want organization (set by the previous process)", got)
	}
}

// TestLevel_SharedAcrossProcesses proves two Sealer instances over the same
// database (standing in for two server processes) agree on an
// organisation's key level without any process-to-process signal beyond the
// database itself, and that Provider instances built over each one
// converge on a single KEK once the level says to — the gap this closes:
// before the level was persisted, two processes could each act on their own
// view of it, one still believing "user" while the other had already moved
// the organisation to "organization", each creating its own KEK for what
// should have been one shared domain.
func TestLevel_SharedAcrossProcesses(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	// Real server processes sharing a database also share the same root key
	// (the same KMS key, or the same local root key file) — that part of
	// "two processes" is not what this test is about, so both Sealers here
	// are built over one root, the way two real processes would be; only
	// the level (this test's actual subject) previously lived in the
	// process's own memory and would not have been shared.
	_, root, _ := testSealerWithRoot(t, pool)
	audit1, audit2 := &recAudit{}, &recAudit{}
	seal1 := sealer.New(root, audit1, newStore(pool))
	seal2 := sealer.New(root, audit2, newStore(pool))
	org := randID(t, "org")

	l1, err := seal1.Level(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	l2, err := seal2.Level(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	if l1 != sealer.LevelUser || l2 != sealer.LevelUser {
		t.Fatalf("default level: seal1=%v seal2=%v, want both LevelUser", l1, l2)
	}

	admin1 := NewAdmin(pool, seal1, org, nil)
	if _, err := admin1.ChangeLevel(ctx, sealer.LevelOrg, "admin", true); err != nil {
		t.Fatalf("ChangeLevel via seal1: %v", err)
	}

	l2, err = seal2.Level(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	if l2 != sealer.LevelOrg {
		t.Fatalf("seal2 still sees %v after seal1's ChangeLevel — level not shared across processes", l2)
	}

	// Two Providers, each writing through its own Sealer, must still both
	// read the shared level fresh and converge on the same organisation-wide
	// KEK, not fall back to creating a per-user KEK for whichever one had a
	// stale view.
	alice := sealer.Scope{Org: org, User: "alice"}
	bob := sealer.Scope{Org: org, User: "bob"}
	pa := New(pool, seal1, alice, nil)
	pb := New(pool, seal2, bob, nil)
	if _, err := pa.Write(ctx, providerRef("s"), secretOf("alice-value")); err != nil {
		t.Fatalf("alice Write: %v", err)
	}
	if _, err := pb.Write(ctx, providerRef("s"), secretOf("bob-value")); err != nil {
		t.Fatalf("bob Write: %v", err)
	}
	aRow, err := pa.db.byVersion(ctx, alice, "s", 1)
	if err != nil {
		t.Fatal(err)
	}
	bRow, err := pb.db.byVersion(ctx, bob, "s", 1)
	if err != nil {
		t.Fatal(err)
	}
	if aRow.kekID != bRow.kekID {
		t.Fatalf("alice's KEK %s != bob's KEK %s at organization level across two Sealer instances — the level was not actually shared", aRow.kekID, bRow.kekID)
	}
}

// TestPurge_ReclaimsKEKThatOnlyProtectedErasedVersions proves crypto-erasure
// is actually final: a KEK that only ever wrapped versions which are now
// erased must become purgeable — not kept alive forever by rows that no
// longer have anything for it to protect. erase clears a row's kek_id
// (not only its wrapped_dek) precisely so Each, Purge's usage scan, stops
// counting it; ChangeLevel is what retires the per-user KEK here (Purge
// only ever considers retired KEKs), standing in for whatever real
// workflow eventually retires it.
func TestPurge_ReclaimsKEKThatOnlyProtectedErasedVersions(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	org := randID(t, "org")
	scope := sealer.Scope{Org: org, User: "alice"}
	p := New(pool, seal, scope, nil)
	admin := NewAdmin(pool, seal, org, nil)
	c := canary.New()

	m1, err := p.Write(ctx, providerRef("secret"), secretOf(c.Value(1)))
	if err != nil {
		t.Fatalf("Write v1: %v", err)
	}
	writtenRow, err := p.db.byVersion(ctx, scope, "secret", 1)
	if err != nil {
		t.Fatal(err)
	}
	onlyKEK := writtenRow.kekID

	if err := p.Erase(ctx, providerRefVersion("secret", m1.Version)); err != nil {
		t.Fatalf("Erase v1: %v", err)
	}
	erasedRow, err := p.db.byVersion(ctx, scope, "secret", 1)
	if err != nil {
		t.Fatal(err)
	}
	if erasedRow.kekID != "" {
		t.Fatalf("erased row still names kek_id %q, want cleared", erasedRow.kekID)
	}

	// Retire alice's per-user KEK by moving the organisation to a coarser
	// level — Purge never touches an active KEK, so this is what makes
	// onlyKEK a candidate at all.
	if _, err := admin.ChangeLevel(ctx, sealer.LevelOrg, "admin", true); err != nil {
		t.Fatalf("ChangeLevel: %v", err)
	}
	if _, err := admin.Purge(ctx, "admin"); err != nil {
		t.Fatalf("Purge: %v", err)
	}

	if _, err := p.db.Get(ctx, org, onlyKEK); err == nil {
		t.Fatalf("KEK %s survived Purge even though only an erased version ever referenced it — crypto-erasure is not final", onlyKEK)
	}
}

// TestChangeLevel_ActsOnlyOnAdminsOwnOrg is the authorization-boundary
// regression this Admin was missing when ChangeLevel took a full
// sealer.LevelChange: a caller could set c.Org to any string, independent
// of which Admin they called it on, and move a DIFFERENT organisation's key
// level. Admin.ChangeLevel no longer takes an Org at all — this proves
// there is no argument left that could redirect it: changing org B's level
// through an Admin built for org A must not be observable at all — org B's
// level must stay unchanged.
func TestChangeLevel_ActsOnlyOnAdminsOwnOrg(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, _ := testSealer(t, pool)
	orgA, orgB := randID(t, "org"), randID(t, "org")
	adminA := NewAdmin(pool, seal, orgA, nil)

	if _, err := adminA.ChangeLevel(ctx, sealer.LevelOrg, "admin", true); err != nil {
		t.Fatalf("ChangeLevel on orgA: %v", err)
	}
	if got, err := seal.Level(ctx, orgA); err != nil {
		t.Fatal(err)
	} else if got != sealer.LevelOrg {
		t.Fatalf("orgA level = %v, want LevelOrg — the change should have applied to it", got)
	}
	if got, err := seal.Level(ctx, orgB); err != nil {
		t.Fatal(err)
	} else if got != sealer.LevelUser {
		t.Fatalf("orgB level = %v, want the untouched default LevelUser — adminA.ChangeLevel affected an organisation it was not built for", got)
	}
}

// TestErrorLeak_LevelChange proves ChangeLevel/Purge never put a secret's
// value into an error or the audit log, using the canary path the same way
// sealer's own TestEventsCarryNoKeyMaterial does, one layer up (through
// Admin, against real Postgres). It provokes real error returns from both
// calls (a refused weakening, a purge with nothing to purge is not an
// error — so the negative case here is the refused ChangeLevel) as well as
// the success path, and scans both the returned errors and the audit
// events.
func TestErrorLeak_LevelChange(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	seal, audit := testSealer(t, pool)
	org := randID(t, "org")
	scope := sealer.Scope{Org: org, User: "alice"}
	p := New(pool, seal, scope, nil)
	var adminLog bytes.Buffer
	admin := NewAdmin(pool, seal, org, slog.New(obs.NewHandler(&adminLog, slog.LevelDebug)))
	c := canary.New()

	if _, err := p.Write(ctx, providerRef("secret"), secretOf(c.Value(1))); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Provoke the error path first: an unconfirmed weakening is refused.
	_, refusedErr := admin.ChangeLevel(ctx, sealer.LevelOrg, "admin", false)
	if !errors.Is(refusedErr, sealer.ErrWeakeningNotConfirmed) {
		t.Fatalf("ChangeLevel(unconfirmed) err = %v, want ErrWeakeningNotConfirmed", refusedErr)
	}
	if c.In(refusedErr.Error()) {
		t.Fatalf("canary leaked into the refused-ChangeLevel error: %v", refusedErr)
	}

	if _, err := admin.ChangeLevel(ctx, sealer.LevelOrg, "admin", true); err != nil {
		t.Fatalf("ChangeLevel: %v", err)
	}
	if _, err := admin.Purge(ctx, "admin"); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	for _, ev := range audit.events {
		if c.In(ev.Action) || c.In(ev.Org) || c.In(ev.Actor) || c.In(ev.Reason) {
			t.Fatalf("canary leaked into an audit event: %+v", ev)
		}
	}
	// Admin's own log lines (ChangeLevel/Purge) were never scanned by any
	// test before this — unlike Provider, which providertest and
	// TestLeakInLogs_BuiltinSurfaces both exercise through obs.Handler.
	if adminLog.Len() == 0 {
		t.Fatal("admin log buffer is empty — the logger is not wired in, the canary check below proves nothing")
	}
	if c.In(adminLog.String()) {
		t.Fatalf("canary leaked into Admin's logs: %s", adminLog.String())
	}
}
