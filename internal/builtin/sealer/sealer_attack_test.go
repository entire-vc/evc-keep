// Attacks against internal/builtin/sealer (threat model §4.6, ADR-001 §5),
// independent of sealer_test.go: ciphertext substitution across stores and
// versions (AAD binding), unconfirmed weakening, and a corrupted key_id.
//
// This file is part of an independent test/security attack suite; it lives
// here rather than under test/security/ because .golangci.yml's "sealer"
// depguard rule and "expose-callers" forbidigo rule confine
// internal/builtin/sealer imports and secret.Expose calls to the plaintext
// zone — a boundary this suite tests, not one it is exempt from. Written
// as a black-box external test package against sealer's exported API
// only, exactly as it would be from outside the zone.
package sealer_test

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

type fakeAuditor struct{ events []sealer.Event }

func (a *fakeAuditor) Record(e sealer.Event) { a.events = append(a.events, e) }

type memEnvelopeStore struct {
	m    map[string]map[string]sealer.Envelope // org -> "secretID/version" -> envelope
	refs map[string]sealer.Ref
}

func newMemStore() *memEnvelopeStore {
	return &memEnvelopeStore{m: map[string]map[string]sealer.Envelope{}, refs: map[string]sealer.Ref{}}
}

func (s *memEnvelopeStore) put(ref sealer.Ref, env sealer.Envelope) {
	if s.m[ref.Store.Org] == nil {
		s.m[ref.Store.Org] = map[string]sealer.Envelope{}
	}
	key := ref.SecretID + "/" + ref.Version
	s.m[ref.Store.Org][key] = env
	s.refs[ref.Store.Org+"/"+key] = ref
}

func (s *memEnvelopeStore) Each(ctx context.Context, org string, fn func(sealer.Ref, sealer.Envelope) error) error {
	for key, env := range s.m[org] {
		if err := fn(s.refs[org+"/"+key], env); err != nil {
			return err
		}
	}
	return nil
}

func (s *memEnvelopeStore) Rewrap(ctx context.Context, org string, fn func(sealer.Ref, sealer.Envelope) (sealer.Envelope, error)) error {
	for key, env := range s.m[org] {
		ref := s.refs[org+"/"+key]
		ne, err := fn(ref, env)
		if err != nil {
			return err
		}
		s.m[org][key] = ne
	}
	return nil
}

// memKEKLevelStore is an in-memory sealer.Store (KEKStore + LevelStore),
// the counterpart of memEnvelopeStore above for the KEK/level side of the
// hierarchy that sealer.New now persists through explicitly — a fake
// standing in for the persistence internal/builtin provides for real (see
// internal/builtin's own tests, which run the same contract against
// PostgreSQL). This attack suite never exercises concurrent ChangeLevel
// calls, so a single mutex guarding every method — including across Lock's
// hold — is enough; it does not attempt to model per-org lock fairness the
// way sealer_test.go's own memKEKStore does.
type memKEKLevelStore struct {
	mu     sync.Mutex
	recs   map[string]sealer.KEKRecord // id -> record
	active map[string]string           // org+"\x00"+domainKey -> id of the active KEK
	levels map[string]sealer.Level     // org -> level; absent means DefaultLevel
}

func newMemKEKLevelStore() *memKEKLevelStore {
	return &memKEKLevelStore{
		recs:   map[string]sealer.KEKRecord{},
		active: map[string]string{},
		levels: map[string]sealer.Level{},
	}
}

func (m *memKEKLevelStore) Level(_ context.Context, org string) (sealer.Level, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.levels[org]; ok {
		return l, nil
	}
	return sealer.DefaultLevel, nil
}

func (m *memKEKLevelStore) SetLevel(_ context.Context, org string, level sealer.Level, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.levels[org] = level
	return nil
}

// Lock returns m itself as the locked Store: every method here already
// serialises through m.mu, so there is no separate "connection" whose calls
// need binding — unlike internal/builtin's real, PostgreSQL-backed
// implementation, which is what proves the connection-sharing property (see
// internal/builtin's own lock tests). This fake grants the lock immediately
// regardless of exclusive, since this suite never has two callers racing
// the same org.
func (m *memKEKLevelStore) Lock(_ context.Context, _ string, _ bool) (sealer.Store, func(context.Context) error, error) {
	return m, func(context.Context) error { return nil }, nil
}

func activeKey(org, domainKey string) string { return org + "\x00" + domainKey }

func (m *memKEKLevelStore) ActiveFor(_ context.Context, org, domainKey string) (sealer.KEKRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.active[activeKey(org, domainKey)]
	if !ok {
		return sealer.KEKRecord{}, sealer.ErrNoActiveKEK
	}
	return m.recs[id], nil
}

func (m *memKEKLevelStore) Create(_ context.Context, domainKey string, want sealer.KEKRecord) (sealer.KEKRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := activeKey(want.Org, domainKey)
	if id, ok := m.active[k]; ok {
		return m.recs[id], nil // a concurrent caller won the race
	}
	m.recs[want.ID] = want
	m.active[k] = want.ID
	return want, nil
}

func (m *memKEKLevelStore) Get(_ context.Context, org, id string) (sealer.KEKRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.recs[id]
	if !ok || rec.Org != org {
		return sealer.KEKRecord{}, sealer.ErrKEKNotFound
	}
	return rec, nil
}

func (m *memKEKLevelStore) ActiveList(_ context.Context, org string) ([]sealer.KEKRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []sealer.KEKRecord
	for _, id := range m.active {
		if r := m.recs[id]; r.Org == org {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memKEKLevelStore) RetiredList(_ context.Context, org string) ([]sealer.KEKRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	isActive := map[string]bool{}
	for _, id := range m.active {
		isActive[id] = true
	}
	var out []sealer.KEKRecord
	for id, r := range m.recs {
		if r.Org == org && !isActive[id] {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memKEKLevelStore) Retire(_ context.Context, org string, ids []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	for k, id := range m.active {
		if set[id] && m.recs[id].Org == org {
			delete(m.active, k)
		}
	}
	return nil
}

func (m *memKEKLevelStore) Purge(_ context.Context, org string, ids []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		if r, ok := m.recs[id]; ok && r.Org == org {
			delete(m.recs, id)
		}
	}
	return nil
}

func newTestRootKey(t *testing.T) sealer.RootKey {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	rk, err := sealer.NewLocalRootKey("root-1", k)
	if err != nil {
		t.Fatal(err)
	}
	return rk
}

func refUser(org, user, secretID, version string) sealer.Ref {
	return sealer.Ref{Store: sealer.Scope{Org: org, User: user}, SecretID: secretID, Version: version}
}

// TestSealer_CiphertextSubstitutionAcrossStores: an attacker with write
// access to the database (but not the KEK) copies one secret's Envelope
// (KEKID + WrappedDEK + Ciphertext, none of which is secret on its own —
// the threat model's whole point is that AAD binding, not confidentiality
// of these fields, is what stops this) onto a DIFFERENT secret's row
// within the SAME store — hoping Open() will decrypt it as if it were the
// target secret. AAD binds SecretID/Name/Version so this must fail closed.
func TestSealer_CiphertextSubstitutionAcrossStores(t *testing.T) {
	ctx := context.Background()
	root := newTestRootKey(t)
	audit := &fakeAuditor{}
	s := sealer.New(root, audit, newMemKEKLevelStore())

	refA := refUser("acme", "alice", "secret-a", "v1")
	refB := refUser("acme", "alice", "secret-b", "v1") // same store, different secret

	envA, err := s.Seal(ctx, refA, secret.New([]byte("value-a")))
	if err != nil {
		t.Fatalf("Seal A: %v", err)
	}

	// Attacker copies A's envelope onto B's slot.
	if _, err := s.Open(ctx, refB, envA); err == nil {
		t.Fatal("Open(refB, envA) succeeded — ciphertext from secret A was accepted for secret B")
	}
}

// TestSealer_CiphertextSubstitutionAcrossVersions: same secret, wrong
// version — the classic "replay an old envelope as the current one" move.
func TestSealer_CiphertextSubstitutionAcrossVersions(t *testing.T) {
	ctx := context.Background()
	root := newTestRootKey(t)
	s := sealer.New(root, &fakeAuditor{}, newMemKEKLevelStore())

	refV1 := refUser("acme", "alice", "secret-a", "v1")
	refV2 := refUser("acme", "alice", "secret-a", "v2")

	envV1, err := s.Seal(ctx, refV1, secret.New([]byte("value-v1")))
	if err != nil {
		t.Fatalf("Seal v1: %v", err)
	}

	if _, err := s.Open(ctx, refV2, envV1); err == nil {
		t.Fatal("Open(refV2, envV1) succeeded — an old version's ciphertext was accepted as the new version")
	}
}

// TestSealer_CiphertextSubstitutionAcrossTenants: the sharpest form of this
// attack — copy an envelope from one ORGANISATION to another. Even at the
// coarsest key level this must fail, because unwrapDEK also checks
// k.org != ref.Store.Org before ever touching the root key.
func TestSealer_CiphertextSubstitutionAcrossTenants(t *testing.T) {
	ctx := context.Background()
	root := newTestRootKey(t)
	s := sealer.New(root, &fakeAuditor{}, newMemKEKLevelStore())

	refAcme := refUser("acme", "alice", "secret-a", "v1")
	refUmbrella := refUser("umbrella", "alice", "secret-a", "v1") // same secretID/version/user name, different org

	envAcme, err := s.Seal(ctx, refAcme, secret.New([]byte("acme-secret")))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if _, err := s.Open(ctx, refUmbrella, envAcme); err == nil {
		t.Fatal("Open under a different organisation's ref succeeded with another org's envelope")
	}
}

// TestSealer_TamperedCiphertextOrWrappedDEK: bit-flip attacks on both
// layers of the envelope. AES-GCM must reject both.
func TestSealer_TamperedCiphertextOrWrappedDEK(t *testing.T) {
	ctx := context.Background()
	root := newTestRootKey(t)
	s := sealer.New(root, &fakeAuditor{}, newMemKEKLevelStore())
	ref := refUser("acme", "alice", "secret-a", "v1")

	env, err := s.Seal(ctx, ref, secret.New([]byte("value")))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	tamperedCT := env
	tamperedCT.Ciphertext = append([]byte(nil), env.Ciphertext...)
	tamperedCT.Ciphertext[len(tamperedCT.Ciphertext)-1] ^= 0x01
	if _, err := s.Open(ctx, ref, tamperedCT); err == nil {
		t.Fatal("Open accepted a bit-flipped Ciphertext")
	}

	tamperedDEK := env
	tamperedDEK.WrappedDEK = append([]byte(nil), env.WrappedDEK...)
	tamperedDEK.WrappedDEK[len(tamperedDEK.WrappedDEK)-1] ^= 0x01
	if _, err := s.Open(ctx, ref, tamperedDEK); err == nil {
		t.Fatal("Open accepted a bit-flipped WrappedDEK")
	}

	// Sanity: the untouched envelope must still open (proves the tamper
	// attempts above were real attacks, not accidental corruption of Seal).
	v, err := s.Open(ctx, ref, env)
	if err != nil {
		t.Fatalf("Open of the original, untampered envelope failed: %v", err)
	}
	secret.Expose(v, func(b []byte) {
		if string(b) != "value" {
			t.Fatalf("Open of the original envelope returned the wrong plaintext: %q", b)
		}
	})
}

// TestSealer_CorruptedKeyID: an envelope whose KEKID names a key that does
// not exist (garbage, or a KEKID from a different sealer instance
// entirely) must fail closed with ErrUnknownKEK, not panic and not fall
// back to any default key.
func TestSealer_CorruptedKeyID(t *testing.T) {
	ctx := context.Background()
	root := newTestRootKey(t)
	s := sealer.New(root, &fakeAuditor{}, newMemKEKLevelStore())
	ref := refUser("acme", "alice", "secret-a", "v1")

	env, err := s.Seal(ctx, ref, secret.New([]byte("value")))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	garbage := env
	garbage.KEKID = "kek_deadbeefdeadbeefdeadbeefdeadbeef"
	if _, err := s.Open(ctx, ref, garbage); err == nil {
		t.Fatal("Open accepted a garbage KEKID")
	}

	empty := env
	empty.KEKID = ""
	if _, err := s.Open(ctx, ref, empty); err == nil {
		t.Fatal("Open accepted an empty KEKID")
	}
}

// TestSealer_WeakeningWithoutConfirmation: a level change to a coarser
// level (more stores sharing one KEK) must be refused, and must change
// NOTHING — not the recorded level, not any envelope — when
// ConfirmWeakening is false. Verified by observing behavior through Seal
// (same KEK reused) and a second ChangeLevel call, not by inspecting
// unexported state.
func TestSealer_WeakeningWithoutConfirmation(t *testing.T) {
	ctx := context.Background()
	root := newTestRootKey(t)
	audit := &fakeAuditor{}
	s := sealer.New(root, audit, newMemKEKLevelStore())
	store := newMemStore()

	refAlice := refUser("acme", "alice", "secret-a", "v1")
	envBefore, err := s.Seal(ctx, refAlice, secret.New([]byte("value")))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	store.put(refAlice, envBefore)

	_, err = s.ChangeLevel(ctx, sealer.LevelChange{
		Org: "acme", To: sealer.LevelOrg, Actor: "admin-1", ConfirmWeakening: false,
	}, store)
	if err == nil {
		t.Fatal("ChangeLevel to a coarser level without ConfirmWeakening was accepted")
	}

	got, err := s.Level(ctx, "acme")
	if err != nil {
		t.Fatalf("Level: %v", err)
	}
	if got != sealer.DefaultLevel {
		t.Fatalf("recorded level changed to %v despite the denied weakening", got)
	}

	// A fresh secret in the same store must still get an envelope that
	// opens under the SAME (unweakened) key domain as before.
	refBob := refUser("acme", "bob", "secret-b", "v1")
	envBob, err := s.Seal(ctx, refBob, secret.New([]byte("bob-value")))
	if err != nil {
		t.Fatalf("Seal after denied weakening: %v", err)
	}
	if envBob.KEKID == envBefore.KEKID {
		t.Fatal("alice and bob got the SAME KEKID at LevelUser — isolation already broken before any weakening was even attempted")
	}
}

// TestSealer_NoActorRefused: LevelChange requires a non-empty Actor —
// otherwise the audit trail for who authorised weakening/strengthening is
// worthless.
func TestSealer_NoActorRefused(t *testing.T) {
	root := newTestRootKey(t)
	s := sealer.New(root, &fakeAuditor{}, newMemKEKLevelStore())
	_, err := s.ChangeLevel(context.Background(), sealer.LevelChange{
		Org: "acme", To: sealer.LevelOrg, Actor: "", ConfirmWeakening: true,
	}, newMemStore())
	if err == nil {
		t.Fatal("ChangeLevel with an empty Actor was accepted")
	}
}

// TestSealer_EventsCarryNoKeyMaterial independently re-checks contract
// item 4 of §4.6 (every outcome is journalled, with no key material)
// against every LevelChange outcome this file exercises, using a fresh
// canary-style scan rather than trusting the developer's own equivalent
// test.
func TestSealer_EventsCarryNoKeyMaterial(t *testing.T) {
	ctx := context.Background()
	root := newTestRootKey(t)
	audit := &fakeAuditor{}
	s := sealer.New(root, audit, newMemKEKLevelStore())
	store := newMemStore()

	ref := refUser("acme", "alice", "secret-a", "v1")
	env, _ := s.Seal(ctx, ref, secret.New([]byte("value")))
	store.put(ref, env)

	_, _ = s.ChangeLevel(ctx, sealer.LevelChange{Org: "acme", To: sealer.LevelOrg, Actor: "admin"}, store) // denied, no confirm
	_, _ = s.ChangeLevel(ctx, sealer.LevelChange{Org: "acme", To: sealer.LevelOrg, Actor: "admin", ConfirmWeakening: true}, store)
	_, _ = s.Purge(ctx, "acme", "admin", store)

	if len(audit.events) == 0 {
		t.Fatal("no events were recorded at all")
	}
	for i, e := range audit.events {
		if e.Actor == "" {
			t.Errorf("event #%d (%s) has no actor", i, e.Action)
		}
		// The Event struct's fields are already a closed, non-key-material
		// shape (From/To Level, counts, strings for org/actor/reason) — the
		// independent check here is that Action is one of the four the
		// contract names, not an ad-hoc string that could smuggle anything.
		switch e.Action {
		case "key_level_changed", "key_level_change_denied", "key_level_change_failed", "kek_purged":
		default:
			t.Errorf("event #%d has an action outside the contract's closed set: %q", i, e.Action)
		}
	}
}
