package sealer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/pkg/secret"
)

// ── fixtures ────────────────────────────────────────────────────────────────

type recAudit struct{ events []Event }

func (a *recAudit) Record(e Event) { a.events = append(a.events, e) }

func (a *recAudit) last(t *testing.T) Event {
	t.Helper()
	if len(a.events) == 0 {
		t.Fatal("no audit event recorded")
	}
	return a.events[len(a.events)-1]
}

// memStore is an in-memory EnvelopeStore. failAfter > 0 makes Rewrap fail
// after that many replacements, to simulate a crash half-way.
type memStore struct {
	refs      []Ref
	envs      map[string]Envelope
	failAfter int
}

func newMemStore() *memStore { return &memStore{envs: map[string]Envelope{}} }

func refKey(r Ref) string { return r.Store.key() + "#" + r.SecretID + "@" + r.Version }

func (m *memStore) put(r Ref, e Envelope) {
	if _, ok := m.envs[refKey(r)]; !ok {
		m.refs = append(m.refs, r)
	}
	m.envs[refKey(r)] = e
}

func (m *memStore) get(r Ref) Envelope { return m.envs[refKey(r)] }

func (m *memStore) Each(_ context.Context, org string, fn func(Ref, Envelope) error) error {
	for _, r := range m.refs {
		if r.Store.Org == org {
			if err := fn(r, m.get(r)); err != nil {
				return err
			}
		}
	}
	return nil
}

var errCrash = errors.New("store crashed")

func (m *memStore) Rewrap(_ context.Context, org string, fn func(Ref, Envelope) (Envelope, error)) error {
	n := 0
	for _, r := range m.refs {
		if r.Store.Org != org {
			continue
		}
		if m.failAfter > 0 && n == m.failAfter {
			return errCrash
		}
		e, err := fn(r, m.get(r))
		if err != nil {
			return err
		}
		m.put(r, e)
		n++
	}
	return nil
}

// memKEKStore is an in-memory KEKStore, the counterpart of memStore for the
// KEK side of the hierarchy — same role as memStore already plays for
// EnvelopeStore in these tests: a fake standing in for the persistence
// internal/builtin provides for real (see internal/builtin's own tests,
// which run the same contract against PostgreSQL).
type memKEKStore struct {
	mu         sync.Mutex
	recs       map[string]KEKRecord     // id -> record
	active     map[string]string        // org+"\x00"+domainKey -> id of the active KEK
	levels     map[string]Level         // org -> level; absent means DefaultLevel
	levelLocks map[string]*sync.RWMutex // org -> its Lock's real.mutex, created on first use
}

func newMemKEKStore() *memKEKStore {
	return &memKEKStore{recs: map[string]KEKRecord{}, active: map[string]string{}, levels: map[string]Level{}, levelLocks: map[string]*sync.RWMutex{}}
}

func (m *memKEKStore) Level(_ context.Context, org string) (Level, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.levels[org]; ok {
		return l, nil
	}
	return DefaultLevel, nil
}

func (m *memKEKStore) SetLevel(_ context.Context, org string, level Level, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.levels[org] = level
	return nil
}

// Lock's in-memory implementation uses one sync.RWMutex per org, separate
// from the mutex guarding this fake's maps (m.mu) — Level/SetLevel/ActiveFor
// etc. all take m.mu themselves and are called by ChangeLevel and Seal while
// a Lock call is held, so reusing m.mu here would deadlock the same
// goroutine against itself. internal/builtin's real, PostgreSQL-backed
// implementation is what proves the cross-process locking property (see
// internal/builtin's own level tests) — this fake only needs to be correct
// for one process's goroutines, which sync.RWMutex already is.
// Lock returns m itself as the locked Store: this fake already serialises
// every method through m.mu (a different mutex than the org-level one
// below), so there is no separate "connection" whose calls need binding —
// unlike internal/builtin's real, PostgreSQL-backed implementation, which
// is what proves the connection-sharing property (see internal/builtin's
// own lock tests).
func (m *memKEKStore) Lock(_ context.Context, org string, exclusive bool) (Store, func(context.Context) error, error) {
	m.mu.Lock()
	l, ok := m.levelLocks[org]
	if !ok {
		l = &sync.RWMutex{}
		m.levelLocks[org] = l
	}
	m.mu.Unlock()

	if exclusive {
		l.Lock()
		return m, func(context.Context) error { l.Unlock(); return nil }, nil
	}
	l.RLock()
	return m, func(context.Context) error { l.RUnlock(); return nil }, nil
}

func activeKey(org, domainKey string) string { return org + "\x00" + domainKey }

func (m *memKEKStore) ActiveFor(_ context.Context, org, domainKey string) (KEKRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.active[activeKey(org, domainKey)]
	if !ok {
		return KEKRecord{}, ErrNoActiveKEK
	}
	return m.recs[id], nil
}

func (m *memKEKStore) Create(_ context.Context, domainKey string, want KEKRecord) (KEKRecord, error) {
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

func (m *memKEKStore) Get(_ context.Context, org, id string) (KEKRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.recs[id]
	if !ok || rec.Org != org {
		return KEKRecord{}, ErrKEKNotFound
	}
	return rec, nil
}

func (m *memKEKStore) ActiveList(_ context.Context, org string) ([]KEKRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []KEKRecord
	for _, id := range m.active {
		if r := m.recs[id]; r.Org == org {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memKEKStore) RetiredList(_ context.Context, org string) ([]KEKRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	isActive := map[string]bool{}
	for _, id := range m.active {
		isActive[id] = true
	}
	var out []KEKRecord
	for id, r := range m.recs {
		if r.Org == org && !isActive[id] {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *memKEKStore) Retire(_ context.Context, org string, ids []string) error {
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

func (m *memKEKStore) Purge(_ context.Context, org string, ids []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		if r, ok := m.recs[id]; ok && r.Org == org {
			delete(m.recs, id)
		}
	}
	return nil
}

func canary(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return []byte("kc" + hex.EncodeToString(b))
}

func newSealer(t *testing.T) (*Sealer, *recAudit) {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	root, err := NewLocalRootKey("root-test", k)
	if err != nil {
		t.Fatal(err)
	}
	a := &recAudit{}
	return New(root, a, newMemKEKStore()), a
}

type sealed struct {
	ref   Ref
	value []byte
}

// world seals secrets in every kind of store of one organisation.
type world struct {
	s     *Sealer
	audit *recAudit
	st    *memStore
	alice []sealed
	bob   []sealed
	all   []sealed
}

const org = "PROTO"

var (
	aliceStore = Scope{Org: org, User: "alice"}
	bobStore   = Scope{Org: org, User: "bob"}
	projStore  = Scope{Org: org, Workspace: "w1", Project: "shop"}
	proj2Store = Scope{Org: org, Workspace: "w1", Project: "blog"}
	wsStore    = Scope{Org: org, Workspace: "w1"}
	orgStore   = Scope{Org: org}
)

func (w *world) seal(t *testing.T, store Scope, id string) sealed {
	t.Helper()
	r := Ref{Store: store, SecretID: id, Name: strings.ToUpper(id), Version: "1"}
	v := canary(t)
	e, err := w.s.Seal(context.Background(), r, secret.New(v))
	if err != nil {
		t.Fatalf("Seal %s: %v", id, err)
	}
	w.st.put(r, e)
	x := sealed{ref: r, value: v}
	w.all = append(w.all, x)
	return x
}

func newWorld(t *testing.T) *world {
	t.Helper()
	s, a := newSealer(t)
	w := &world{s: s, audit: a, st: newMemStore()}
	for _, id := range []string{"a1", "a2"} {
		w.alice = append(w.alice, w.seal(t, aliceStore, id))
	}
	for _, id := range []string{"b1", "b2"} {
		w.bob = append(w.bob, w.seal(t, bobStore, id))
	}
	w.seal(t, projStore, "p1")
	w.seal(t, proj2Store, "p2")
	w.seal(t, wsStore, "w1")
	w.seal(t, orgStore, "o1")
	return w
}

// allOpen asserts that every sealed secret opens to its original value.
func (w *world) allOpen(t *testing.T) {
	t.Helper()
	for _, x := range w.all {
		v, err := w.s.Open(context.Background(), x.ref, w.st.get(x.ref))
		if err != nil {
			t.Fatalf("Open %s after level change: %v", x.ref.SecretID, err)
		}
		if !v.Equal(secret.New(x.value)) {
			t.Fatalf("Open %s: value differs from the one sealed", x.ref.SecretID)
		}
	}
}

// ── per-user KEK isolation: compromise of one user's KEK ─────────────────────

// kekOf plays the attacker who stole the plaintext KEK wrapping e.
func kekOf(t *testing.T, s *Sealer, e Envelope) []byte {
	t.Helper()
	rec, err := s.store.Get(context.Background(), org, e.KEKID)
	if err != nil {
		t.Fatalf("no KEK %s: %v", e.KEKID, err)
	}
	b, err := s.unwrapKEK(rec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// readsWith reports whether stolen KEK bytes decrypt x. The attacker knows
// the envelope format and the AAD layout; only keys are secret.
func readsWith(stolen []byte, x sealed, e Envelope) bool {
	ka, err := newAEAD(stolen)
	if err != nil {
		return false
	}
	dek, err := open(ka, e.WrappedDEK, dekAAD(x.ref, e.KEKID))
	if err != nil {
		return false
	}
	da, err := newAEAD(dek)
	if err != nil {
		return false
	}
	p, err := open(da, e.Ciphertext, valueAAD(x.ref))
	return err == nil && bytes.Equal(p, x.value)
}

// c6Violations steals Alice's KEK and returns the secrets of Bob it reads.
// It fails the test if the stolen key does not read Alice's own secrets: an
// attack that reads nothing proves nothing.
func c6Violations(t *testing.T, w *world) []string {
	t.Helper()
	stolen := kekOf(t, w.s, w.st.get(w.alice[0].ref))
	for _, x := range w.alice {
		if !readsWith(stolen, x, w.st.get(x.ref)) {
			t.Fatalf("attack harness broken: Alice's own KEK does not read %s", x.ref.SecretID)
		}
	}
	var got []string
	for _, x := range w.bob {
		if readsWith(stolen, x, w.st.get(x.ref)) {
			got = append(got, x.ref.SecretID)
		}
	}
	return got
}

func TestC6_UserKEKCompromiseDoesNotRevealOtherUser(t *testing.T) {
	w := newWorld(t)
	l, err := w.s.Level(context.Background(), org)
	if err != nil {
		t.Fatal(err)
	}
	if l != LevelUser {
		t.Fatalf("default level = %v, want user", l)
	}
	if v := c6Violations(t, w); len(v) != 0 {
		t.Fatalf("KEK isolation: Alice's KEK reads Bob's secrets %v", v)
	}
	ka, kb := w.st.get(w.alice[0].ref).KEKID, w.st.get(w.bob[0].ref).KEKID
	if ka == kb {
		t.Fatalf("KEK isolation: Alice and Bob share KEK %s", ka)
	}
}

// The isolation check must be able to fail: at the organisation level Alice and Bob
// share a KEK by design, and the same check has to report it.
func TestC6_CheckDetectsSharedKEK(t *testing.T) {
	s, _ := newSealer(t)
	if _, err := s.ChangeLevel(context.Background(), LevelChange{Org: org, To: LevelOrg, Actor: "admin", ConfirmWeakening: true}, newMemStore()); err != nil {
		t.Fatal(err)
	}
	w := &world{s: s, audit: &recAudit{}, st: newMemStore()}
	w.alice = append(w.alice, w.seal(t, aliceStore, "a1"))
	w.bob = append(w.bob, w.seal(t, bobStore, "b1"))
	if v := c6Violations(t, w); len(v) != 1 {
		t.Fatalf("isolation check missed a shared KEK: violations %v, want [b1]", v)
	}
}

// ── level change: re-wrap without re-encryption ─────────────────────────────

func TestChangeLevel_RoundTripUserOrgUser(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	before := map[string][]byte{}
	kekBefore := map[string]string{}
	for _, x := range w.all {
		e := w.st.get(x.ref)
		before[x.ref.SecretID] = append([]byte(nil), e.Ciphertext...)
		kekBefore[x.ref.SecretID] = e.KEKID
	}

	// Down to organisation: every DEK now under one KEK.
	res, err := w.s.ChangeLevel(ctx, LevelChange{Org: org, To: LevelOrg, Actor: "admin", ConfirmWeakening: true}, w.st)
	if err != nil {
		t.Fatal(err)
	}
	if res.From != LevelUser || res.To != LevelOrg || res.Rewrapped != len(w.all)-1 || res.Unchanged != 1 {
		t.Fatalf("down: result %+v, want user→org, %d rewrapped, 1 unchanged", res, len(w.all)-1)
	}
	w.allOpen(t)
	orgKEK := w.st.get(w.all[len(w.all)-1].ref).KEKID
	for _, x := range w.all {
		e := w.st.get(x.ref)
		if e.KEKID != orgKEK {
			t.Fatalf("down: %s still under %s, want org KEK %s", x.ref.SecretID, e.KEKID, orgKEK)
		}
		if !bytes.Equal(e.Ciphertext, before[x.ref.SecretID]) {
			t.Fatalf("down: ciphertext of %s changed — data was re-encrypted, not re-wrapped", x.ref.SecretID)
		}
	}
	if ev := w.audit.last(t); ev.Action != "key_level_changed" || ev.Actor != "admin" || ev.From != LevelUser || ev.To != LevelOrg {
		t.Fatalf("down: audit event %+v", ev)
	}
	// Five per-store KEKs (alice, bob, shop, blog, w1) are now unused.
	if n, err := w.s.Purge(ctx, org, "admin", w.st); err != nil || n != 5 {
		t.Fatalf("down: purge destroyed %d KEKs (err %v), want 5", n, err)
	}
	w.allOpen(t)

	// Back to user: fresh per-store KEKs, isolation restored.
	res, err = w.s.ChangeLevel(ctx, LevelChange{Org: org, To: LevelUser, Actor: "admin"}, w.st)
	if err != nil {
		t.Fatalf("up: strengthening must not need confirmation: %v", err)
	}
	if res.Rewrapped != len(w.all)-1 {
		t.Fatalf("up: result %+v", res)
	}
	w.allOpen(t)
	seen := map[string]string{}
	for _, x := range w.all {
		e := w.st.get(x.ref)
		if !bytes.Equal(e.Ciphertext, before[x.ref.SecretID]) {
			t.Fatalf("up: ciphertext of %s changed", x.ref.SecretID)
		}
		if e.KEKID == kekBefore[x.ref.SecretID] && x.ref.Store != orgStore {
			t.Fatalf("up: %s is back under purged KEK %s", x.ref.SecretID, e.KEKID)
		}
		seen[x.ref.Store.key()] = e.KEKID
	}
	ids := map[string]bool{}
	for _, id := range seen {
		ids[id] = true
	}
	if len(ids) != len(seen) {
		t.Fatalf("up: stores share KEKs at user level: %v", seen)
	}
	if v := c6Violations(t, w); len(v) != 0 {
		t.Fatalf("up: KEK isolation broken after round trip: %v", v)
	}

	// Running the same change again moves nothing.
	res, err = w.s.ChangeLevel(ctx, LevelChange{Org: org, To: LevelUser, Actor: "admin"}, w.st)
	if err != nil || res.Rewrapped != 0 || res.Unchanged != len(w.all) {
		t.Fatalf("repeat: %+v, %v", res, err)
	}
}

func TestChangeLevel_WeakeningNeedsConfirmation(t *testing.T) {
	for _, to := range []Level{LevelProject, LevelWorkspace, LevelOrg} {
		t.Run(to.String(), func(t *testing.T) {
			w := newWorld(t)
			kek := map[string]string{}
			for _, x := range w.all {
				kek[x.ref.SecretID] = w.st.get(x.ref).KEKID
			}
			_, err := w.s.ChangeLevel(context.Background(), LevelChange{Org: org, To: to, Actor: "admin"}, w.st)
			if !errors.Is(err, ErrWeakeningNotConfirmed) {
				t.Fatalf("user→%v without confirmation: err %v, want ErrWeakeningNotConfirmed", to, err)
			}
			l, err := w.s.Level(context.Background(), org)
			if err != nil {
				t.Fatal(err)
			}
			if l != LevelUser {
				t.Fatalf("level changed to %v on a refused change", l)
			}
			for _, x := range w.all {
				if w.st.get(x.ref).KEKID != kek[x.ref.SecretID] {
					t.Fatalf("%s re-wrapped on a refused change", x.ref.SecretID)
				}
			}
			if ev := w.audit.last(t); ev.Action != "key_level_change_denied" || ev.Actor != "admin" {
				t.Fatalf("refused change not journaled: %+v", ev)
			}
		})
	}
}

func TestChangeLevel_NeedsActor(t *testing.T) {
	w := newWorld(t)
	if _, err := w.s.ChangeLevel(context.Background(), LevelChange{Org: org, To: LevelOrg, ConfirmWeakening: true}, w.st); !errors.Is(err, ErrNoActor) {
		t.Fatalf("err %v, want ErrNoActor", err)
	}
}

// A crash half-way leaves a mix of old and new KEKs. Everything must still
// open, nothing may be retired or purged, and a rerun must finish the job.
func TestChangeLevel_InterruptedIsResumable(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	w.st.failAfter = 3
	_, err := w.s.ChangeLevel(ctx, LevelChange{Org: org, To: LevelOrg, Actor: "admin", ConfirmWeakening: true}, w.st)
	if !errors.Is(err, errCrash) {
		t.Fatalf("err %v, want the store crash", err)
	}
	if ev := w.audit.last(t); ev.Action != "key_level_change_failed" {
		t.Fatalf("failed change not journaled: %+v", ev)
	}
	w.allOpen(t)
	if n, err := w.s.Purge(ctx, org, "admin", w.st); err != nil || n != 0 {
		t.Fatalf("purge after a crash destroyed %d KEKs (err %v)", n, err)
	}
	w.allOpen(t)

	w.st.failAfter = 0
	res, err := w.s.ChangeLevel(ctx, LevelChange{Org: org, To: LevelOrg, Actor: "admin"}, w.st)
	if err != nil {
		t.Fatalf("rerun: %v", err)
	}
	if res.Rewrapped+res.Unchanged != len(w.all) || res.Unchanged < 3 {
		t.Fatalf("rerun: %+v", res)
	}
	w.allOpen(t)
}

// Purge must keep a retired KEK while any envelope still refers to it.
func TestPurge_KeepsReferencedKEK(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	w.st.failAfter = 1
	_, _ = w.s.ChangeLevel(ctx, LevelChange{Org: org, To: LevelOrg, Actor: "admin", ConfirmWeakening: true}, w.st)
	// Mark every remaining active KEK retired, as if the change had
	// completed without the envelope store's Rewrap finishing.
	actives, err := w.s.store.ActiveList(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(actives))
	for i, k := range actives {
		ids[i] = k.ID
	}
	if err := w.s.store.Retire(ctx, org, ids); err != nil {
		t.Fatal(err)
	}
	if _, err := w.s.Purge(ctx, org, "admin", w.st); err != nil {
		t.Fatal(err)
	}
	w.allOpen(t)
}

// ── domains ─────────────────────────────────────────────────────────────────

func TestDomain(t *testing.T) {
	ws := Scope{Org: org, Workspace: "w1"}
	cases := []struct {
		store Scope
		want  map[Level]Scope
	}{
		{aliceStore, map[Level]Scope{LevelUser: aliceStore, LevelProject: orgStore, LevelWorkspace: orgStore, LevelOrg: orgStore}},
		{projStore, map[Level]Scope{LevelUser: projStore, LevelProject: projStore, LevelWorkspace: ws, LevelOrg: orgStore}},
		{wsStore, map[Level]Scope{LevelUser: wsStore, LevelProject: wsStore, LevelWorkspace: wsStore, LevelOrg: orgStore}},
		{orgStore, map[Level]Scope{LevelUser: orgStore, LevelProject: orgStore, LevelWorkspace: orgStore, LevelOrg: orgStore}},
	}
	for _, c := range cases {
		for l, want := range c.want {
			if got := Domain(c.store, l); got != want {
				t.Errorf("Domain(%s, %v) = %s, want %s", c.store.key(), l, got.key(), want.key())
			}
		}
	}
}

func TestParseLevel(t *testing.T) {
	for _, l := range []Level{LevelUser, LevelProject, LevelWorkspace, LevelOrg} {
		got, err := ParseLevel(l.String())
		if err != nil || got != l {
			t.Errorf("ParseLevel(%q) = %v, %v", l.String(), got, err)
		}
	}
	if _, err := ParseLevel("tenant"); !errors.Is(err, ErrInvalidLevel) {
		t.Errorf("ParseLevel(tenant) err %v", err)
	}
	if !LevelUser.Weakens(LevelOrg) || LevelOrg.Weakens(LevelUser) || LevelUser.Weakens(LevelUser) {
		t.Error("Weakens order is wrong")
	}
}

// TestActiveKEK_RejectsDomainMismatch guards against a store-level
// corruption that would otherwise share a KEK across two domains silently:
// if a KEKStore's domain index ever points a domainKey at a KEKRecord whose
// own Domain field says otherwise (a bug in a KEKStore implementation, or
// a corrupted domain_key column in the real PostgreSQL-backed one — not
// something normal application code can trigger through the sealer's own
// API), activeKEK must refuse to use it rather than unwrap and seal a new
// DEK under a KEK that belongs to someone else's domain.
func TestActiveKEK_RejectsDomainMismatch(t *testing.T) {
	ctx := context.Background()
	s, _ := newSealer(t)
	ms := s.store.(*memKEKStore)

	bobKEK, bobBytes, err := s.activeKEK(ctx, bobStore)
	if err != nil {
		t.Fatal(err)
	}
	wipe(bobBytes)

	// Corrupt the store's index: alice's domain key now resolves to bob's
	// KEK record, as if that row's domain_key column had been rewritten —
	// the record's own Domain field still says "bob".
	ms.mu.Lock()
	ms.active[activeKey(org, aliceStore.key())] = bobKEK.ID
	ms.mu.Unlock()

	if _, _, err := s.activeKEK(ctx, aliceStore); !errors.Is(err, ErrUnknownKEK) {
		t.Fatalf("activeKEK(alice) with a domain-mismatched record: err = %v, want ErrUnknownKEK", err)
	}
}

// ── bindings ────────────────────────────────────────────────────────────────

// A wrapped DEK or a ciphertext moved to another secret must not open.
func TestEnvelopeIsBoundToItsSecret(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	a1, a2 := w.alice[0], w.alice[1]
	e1, e2 := w.st.get(a1.ref), w.st.get(a2.ref)
	swaps := map[string]Envelope{
		"wrapped DEK": {KEKID: e1.KEKID, WrappedDEK: e1.WrappedDEK, Ciphertext: e2.Ciphertext},
		"whole":       e1,
	}
	for name, e := range swaps {
		if _, err := w.s.Open(ctx, a2.ref, e); err == nil {
			t.Errorf("%s of a1 opened as a2", name)
		}
	}
	// The wrapped DEK itself is bound to its secret, not only the value.
	if _, err := w.s.unwrapDEK(ctx, a2.ref, Envelope{KEKID: e1.KEKID, WrappedDEK: e1.WrappedDEK}); err == nil {
		t.Error("wrapped DEK of a1 unwraps as a2")
	}
	other := a1.ref
	other.Store = Scope{Org: "EVC", User: "alice"}
	if _, err := w.s.Open(ctx, other, e1); !errors.Is(err, ErrUnknownKEK) {
		t.Errorf("envelope opened in another org: %v", err)
	}
}

// ── nothing secret in events or errors ──────────────────────────────────────

func TestEventsCarryNoKeyMaterial(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	var keys [][]byte
	for _, x := range w.all {
		keys = append(keys, kekOf(t, w.s, w.st.get(x.ref)))
	}
	_, _ = w.s.ChangeLevel(ctx, LevelChange{Org: org, To: LevelOrg, Actor: "admin"}, w.st)
	_, _ = w.s.ChangeLevel(ctx, LevelChange{Org: org, To: LevelOrg, Actor: "admin", ConfirmWeakening: true}, w.st)
	_, _ = w.s.Purge(ctx, org, "admin", w.st)
	dump := fmt.Sprintf("%+v %#v", w.audit.events, w.audit.events)
	for _, x := range w.all {
		if strings.Contains(dump, string(x.value)) {
			t.Fatal("audit events contain a secret value")
		}
	}
	for _, k := range keys {
		for _, enc := range []string{string(k), hex.EncodeToString(k), fmt.Sprintf("%v", k)} {
			if strings.Contains(dump, enc) {
				t.Fatal("audit events contain key material")
			}
		}
	}
	actions := []string{}
	for _, e := range w.audit.events {
		actions = append(actions, e.Action)
	}
	sort.Strings(actions)
	if strings.Join(actions, ",") != "kek_purged,key_level_change_denied,key_level_changed" {
		t.Fatalf("events %v", actions)
	}
}

// Field boundaries must survive encoding: without length prefixes the AAD of
// secret "ab" version "c" would equal that of secret "a" version "bc", and one
// wrapped DEK would unwrap for both.
func TestAADIsUnambiguous(t *testing.T) {
	if bytes.Equal(aad("l", "ab", "c"), aad("l", "a", "bc")) {
		t.Fatal("aad(ab,c) == aad(a,bc)")
	}
	if bytes.Equal(aad("l", "", "x"), aad("l", "x", "")) {
		t.Fatal("aad(,x) == aad(x,)")
	}
	s, _ := newSealer(t)
	ctx := context.Background()
	r1 := Ref{Store: aliceStore, SecretID: "ab", Name: "N", Version: "c"}
	r2 := Ref{Store: aliceStore, SecretID: "a", Name: "N", Version: "bc"}
	e, err := s.Seal(ctx, r1, secret.New(canary(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.unwrapDEK(ctx, r2, e); err == nil {
		t.Fatal("wrapped DEK of (ab, c) unwraps as (a, bc)")
	}
}

// Scope ids are concatenated into the store key that the DEK's AAD carries.
// Without a length prefix on each id, workspace "w1/proj:shop" and workspace
// "w1" + project "shop" render the same key, and an envelope of one store
// opens as an envelope of the other (a direct database write is enough).
func TestScopeKeyIsUnambiguous(t *testing.T) {
	ctx := context.Background()
	colliding := Scope{Org: org, Workspace: "w1/proj:shop"}
	real := Scope{Org: org, Workspace: "w1", Project: "shop"}
	if colliding.validate() != nil || real.validate() != nil {
		t.Fatal("test scopes must both be valid")
	}
	pairs := [][2]Scope{
		{colliding, real},
		{{Org: org + "/user:x"}, {Org: org, User: "x"}},
		{{Org: "a", Workspace: "b"}, {Org: "a/ws:b"}},
	}
	for _, p := range pairs {
		if p[0].key() == p[1].key() {
			t.Errorf("scopes %+v and %+v render the same key %q", p[0], p[1], p[0].key())
		}
	}

	s, _ := newSealer(t)
	rA := Ref{Store: colliding, SecretID: "s1", Name: "N", Version: "1"}
	rB := Ref{Store: real, SecretID: "s1", Name: "N", Version: "1"}
	e, err := s.Seal(ctx, rA, secret.New(canary(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(ctx, rB, e); err == nil {
		t.Fatal("an envelope of store A opened as store B's, whose scope renders the same key")
	}
	if _, err := s.Open(ctx, rA, e); err != nil {
		t.Fatalf("positive control: the envelope must open at its own store: %v", err)
	}
}

// failingLevels makes one step of the key-level persistence fail.
type failingLevels struct {
	Store
	failLock, failLevel, failSet, failActiveList bool
	failRetiredList, failPurge                   bool
}

func (f *failingLevels) RetiredList(ctx context.Context, org string) ([]KEKRecord, error) {
	if f.failRetiredList {
		return nil, errors.New("retired list down")
	}
	return f.Store.RetiredList(ctx, org)
}

func (f *failingLevels) Purge(ctx context.Context, org string, ids []string) error {
	if f.failPurge {
		return errors.New("purge down")
	}
	return f.Store.Purge(ctx, org, ids)
}

func (f *failingLevels) ActiveList(ctx context.Context, org string) ([]KEKRecord, error) {
	if f.failActiveList {
		return nil, errors.New("kek list down")
	}
	return f.Store.ActiveList(ctx, org)
}

func (f *failingLevels) Level(ctx context.Context, org string) (Level, error) {
	if f.failLevel {
		return 0, errors.New("level read down")
	}
	return f.Store.Level(ctx, org)
}

func (f *failingLevels) SetLevel(ctx context.Context, org string, l Level, actor string) error {
	if f.failSet {
		return errors.New("level write down")
	}
	return f.Store.SetLevel(ctx, org, l, actor)
}

func (f *failingLevels) Lock(ctx context.Context, org string, exclusive bool) (Store, func(context.Context) error, error) {
	if f.failLock {
		return nil, nil, errors.New("lock down")
	}
	locked, release, err := f.Store.Lock(ctx, org, exclusive)
	if err != nil {
		return nil, nil, err
	}
	return &failingLevels{Store: locked, failLevel: f.failLevel, failSet: f.failSet, failActiveList: f.failActiveList}, release, nil
}

// A level change that fails before it reaches Rewrap must still leave a
// journal event: an operator who asked for a change and got an error needs to
// find the attempt in the audit trail (threat model 4.6).
func TestChangeLevel_PersistenceFailuresAreAudited(t *testing.T) {
	for _, tc := range []struct {
		name   string
		f      failingLevels
		reason string
	}{
		{"lock", failingLevels{failLock: true}, "lock_failed"},
		{"level read", failingLevels{failLevel: true}, "level_read_failed"},
		{"level write", failingLevels{failSet: true}, "level_write_failed"},
		{"retire", failingLevels{failActiveList: true}, "retire_incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, a := newSealer(t)
			f := tc.f
			f.Store = s.store
			s.store = &f
			_, err := s.ChangeLevel(context.Background(), LevelChange{RequestID: "req-persist", Org: org, To: LevelOrg, Actor: "admin", ConfirmWeakening: true}, newMemStore())
			if err == nil {
				t.Fatal("ChangeLevel succeeded although its persistence failed")
			}
			e := a.last(t)
			if e.RequestID != "req-persist" {
				t.Fatalf("event %s names request id %q; want the id of the request it answers", tc.reason, e.RequestID)
			}
			if e.Action != "key_level_change_failed" || e.Reason != tc.reason {
				t.Fatalf("event = %+v, want key_level_change_failed / %s", e, tc.reason)
			}
			if e.Org != org || e.Actor != "admin" || e.To != LevelOrg {
				t.Fatalf("event = %+v: it must name the organisation, the actor and the target level", e)
			}
		})
	}
}

// A purge that fails part-way is journaled like a level change is, and a purge
// with no actor is refused before it reads anything.
type failingEnvelopes struct{ EnvelopeStore }

func (failingEnvelopes) Each(context.Context, string, func(Ref, Envelope) error) error {
	return errors.New("scan down")
}

func TestPurge_FailureIsAuditedAndNeedsActor(t *testing.T) {
	ctx := context.Background()
	s, a := newSealer(t)
	if _, err := s.Purge(ctx, org, "", newMemStore()); !errors.Is(err, ErrNoActor) {
		t.Fatalf("Purge without an actor: %v, want ErrNoActor", err)
	}
	if len(a.events) != 1 || a.events[0].Action != "kek_purge_failed" || a.events[0].Reason != "no_actor" {
		t.Fatalf("a refused purge must record no_actor: %+v", a.events)
	}
	if _, err := s.Purge(ctx, org, "admin", failingEnvelopes{newMemStore()}); err == nil {
		t.Fatal("Purge succeeded although its scan failed")
	}
	e := a.last(t)
	if e.Action != "kek_purge_failed" || e.Reason != "scan_failed" || e.Org != org || e.Actor != "admin" {
		t.Fatalf("event = %+v, want kek_purge_failed / scan_failed for org and admin", e)
	}
}

// Every step of a purge that can fail is journaled with its own reason. The
// KEKs are retired with nothing referencing them, so an unfailed Purge would
// delete them (the control run below).
func TestPurge_EachFailureStepIsAudited(t *testing.T) {
	ctx := context.Background()
	// retireAll retires every active KEK of a fresh world; nothing references
	// them because the envelope store handed to Purge is empty.
	retireAll := func(t *testing.T) (*world, int) {
		t.Helper()
		w := newWorld(t)
		actives, err := w.s.store.ActiveList(ctx, org)
		if err != nil || len(actives) == 0 {
			t.Fatalf("ActiveList: %d records, %v", len(actives), err)
		}
		ids := make([]string, len(actives))
		for i, k := range actives {
			ids[i] = k.ID
		}
		if err := w.s.store.Retire(ctx, org, ids); err != nil {
			t.Fatal(err)
		}
		return w, len(ids)
	}

	// Control: with nothing failing, every retired KEK is purged.
	w, n := retireAll(t)
	if got, err := w.s.Purge(ctx, org, "admin", newMemStore()); err != nil || got != n {
		t.Fatalf("control Purge = %d, %v; want %d, nil", got, err, n)
	}

	for _, tc := range []struct {
		name   string
		f      failingLevels
		reason string
	}{
		{"retired list", failingLevels{failRetiredList: true}, "list_failed"},
		{"purge", failingLevels{failPurge: true}, "purge_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := retireAll(t)
			f := tc.f
			f.Store = w.s.store
			w.s.store = &f
			if _, err := w.s.Purge(ctx, org, "admin", newMemStore()); err == nil {
				t.Fatal("Purge succeeded although its store failed")
			}
			e := w.audit.last(t)
			if e.Action != "kek_purge_failed" || e.Reason != tc.reason || e.Org != org || e.Actor != "admin" {
				t.Fatalf("event = %+v, want kek_purge_failed / %s for org and admin", e, tc.reason)
			}
		})
	}
}

// decodeScopeKey is an independent reader of the documented key format
// ("org:<len>:<org>[/user:<len>:<id> | /ws:<len>:<id>[/proj:<len>:<id>]]").
// A key that does not parse back to the scope it came from is ambiguous or
// malformed: this catches a missing length prefix on any single field, which
// a comparison of a few hand-picked pairs does not.
func decodeScopeKey(k string) (Scope, bool) {
	var parts [][2]string
	for len(k) > 0 {
		i := strings.IndexByte(k, ':')
		if i < 0 {
			return Scope{}, false
		}
		name := k[:i]
		k = k[i+1:]
		j := strings.IndexByte(k, ':')
		if j < 0 {
			return Scope{}, false
		}
		n, err := strconv.Atoi(k[:j])
		if err != nil || n < 0 || j+1+n > len(k) {
			return Scope{}, false
		}
		parts = append(parts, [2]string{name, k[j+1 : j+1+n]})
		k = k[j+1+n:]
		if k == "" {
			break
		}
		if k[0] != '/' {
			return Scope{}, false
		}
		k = k[1:]
	}
	names := ""
	for _, p := range parts {
		names += p[0] + ","
	}
	switch names {
	case "org,":
		return Scope{Org: parts[0][1]}, true
	case "org,user,":
		return Scope{Org: parts[0][1], User: parts[1][1]}, true
	case "org,ws,":
		return Scope{Org: parts[0][1], Workspace: parts[1][1]}, true
	case "org,ws,proj,":
		return Scope{Org: parts[0][1], Workspace: parts[1][1], Project: parts[2][1]}, true
	}
	return Scope{}, false
}

func TestScopeKeyRoundTripsForAdversarialIDs(t *testing.T) {
	atoms := []string{"", "x", "abc", ":", "/", "/proj:", "/ws:", "/user:", "3:", "11:", "org:", "1:a", "0:"}
	// A fixed-seed generator, so a failure reproduces: not a source of keys.
	state := 1
	intn := func(n int) int {
		state = state*6364136223846793005 + 1442695040888963407 // wraps, on purpose
		return (state >> 33 & 0x7fffffff) % n
	}
	id := func() string {
		var b strings.Builder
		for n := intn(4); n > 0; n-- {
			b.WriteString(atoms[intn(len(atoms))])
		}
		return b.String()
	}
	seen := map[string]Scope{}
	valid := 0
	for i := 0; i < 60000; i++ {
		var sc Scope
		switch intn(4) {
		case 0:
			sc = Scope{Org: id()}
		case 1:
			sc = Scope{Org: id(), User: id()}
		case 2:
			sc = Scope{Org: id(), Workspace: id()}
		default:
			sc = Scope{Org: id(), Workspace: id(), Project: id()}
		}
		if sc.validate() != nil {
			continue
		}
		valid++
		k := sc.key()
		got, ok := decodeScopeKey(k)
		if !ok || got != sc {
			t.Fatalf("scope %+v renders key %q, which reads back as %+v (ok=%v)", sc, k, got, ok)
		}
		if prev, dup := seen[k]; dup && prev != sc {
			t.Fatalf("scopes %+v and %+v render the same key %q", prev, sc, k)
		}
		seen[k] = sc
	}
	if valid < 1000 {
		t.Fatalf("only %d valid scopes generated", valid)
	}
}

// Every outcome of a level change names the request it answers, so the journal
// pairs outcome and request by id and never by guess.
func TestChangeLevel_OutcomesCarryRequestID(t *testing.T) {
	const id = "req-abc-123"
	for _, tc := range []struct {
		name   string
		change LevelChange
		action string
	}{
		{"changed", LevelChange{Org: org, To: LevelOrg, Actor: "admin", ConfirmWeakening: true}, "key_level_changed"},
		{"denied weakening", LevelChange{Org: org, To: LevelOrg, Actor: "admin"}, "key_level_change_denied"},
		{"denied invalid level", LevelChange{Org: org, To: Level(99), Actor: "admin"}, "key_level_change_denied"},
		{"denied no actor", LevelChange{Org: org, To: LevelOrg, ConfirmWeakening: true}, "key_level_change_denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			w.audit.events = nil
			tc.change.RequestID = id
			_, _ = w.s.ChangeLevel(context.Background(), tc.change, w.st)
			if e := w.audit.last(t); e.Action != tc.action || e.RequestID != id {
				t.Fatalf("outcome %q with request id %q; want %q with %q", e.Action, e.RequestID, tc.action, id)
			}
		})
	}
}

// The OnLocked hook runs once, under the exclusive level lock, before the
// level is read or written, with a deadline.
func TestChangeLevel_OnLockedRunsOnceUnderTheLockBeforeAnyWrite(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	calls := 0
	var held, levelInHook Level
	var hadDeadline, sharedGotIn bool
	var hookBudget time.Duration
	hook := func(hctx context.Context) error {
		calls++
		var dl time.Time
		dl, hadDeadline = hctx.Deadline()
		hookBudget = time.Until(dl)
		levelInHook, _ = w.s.Level(hctx, org)
		got := make(chan struct{})
		go func() {
			_, rel, err := w.s.store.Lock(ctx, org, false)
			if err == nil {
				close(got)
				_ = rel(ctx)
			}
		}()
		select {
		case <-got:
			sharedGotIn = true
		case <-time.After(100 * time.Millisecond):
		}
		held = levelInHook
		return nil
	}
	if _, err := w.s.ChangeLevel(ctx, LevelChange{Org: org, To: LevelOrg, Actor: "admin", ConfirmWeakening: true, OnLocked: hook}, w.st); err != nil {
		t.Fatalf("change: %v", err)
	}
	if calls != 1 {
		t.Fatalf("hook ran %d times, want 1", calls)
	}
	if !hadDeadline {
		t.Fatal("hook context has no deadline")
	}
	if hookBudget <= 10*time.Second || hookBudget > 15*time.Second {
		t.Fatalf("hook deadline is %s away, want about 15s", hookBudget)
	}
	if sharedGotIn {
		t.Fatal("a shared lock was granted while the hook ran: the hook is not under the level lock")
	}
	if held != LevelUser {
		t.Fatalf("level in the hook = %v, want the untouched LevelUser", held)
	}
	if l, _ := w.s.Level(ctx, org); l != LevelOrg {
		t.Fatalf("level after = %v", l)
	}
}

// A failing hook ends the change before it touches anything, releases the lock,
// audits nothing, and does not forward the hook's own text.
func TestChangeLevel_OnLockedFailureStopsBeforeAnyWrite(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	kek := map[string]string{}
	for _, x := range w.all {
		kek[x.ref.SecretID] = w.st.get(x.ref).KEKID
	}
	hookErr := errors.New("backend echoed kcprobe-hook-text")
	_, err := w.s.ChangeLevel(ctx, LevelChange{Org: org, To: LevelOrg, Actor: "admin", ConfirmWeakening: true,
		OnLocked: func(context.Context) error { return hookErr }}, w.st)
	if !errors.Is(err, ErrOnLocked) {
		t.Fatalf("err %v, want ErrOnLocked", err)
	}
	if errors.Is(err, hookErr) || strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), "kcprobe-hook-text") {
		t.Fatalf("hook error text forwarded: %v", err)
	}
	if l, _ := w.s.Level(ctx, org); l != LevelUser {
		t.Fatalf("level changed to %v after a failed hook", l)
	}
	for _, x := range w.all {
		if w.st.get(x.ref).KEKID != kek[x.ref.SecretID] {
			t.Fatalf("%s re-wrapped after a failed hook", x.ref.SecretID)
		}
	}
	if len(w.audit.events) != 0 {
		t.Fatalf("failed hook audited: %+v", w.audit.events)
	}
	// The lock was released: the same change goes through without a hook.
	done := make(chan error, 1)
	go func() {
		_, err := w.s.ChangeLevel(ctx, LevelChange{Org: org, To: LevelOrg, Actor: "admin", ConfirmWeakening: true}, w.st)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("rerun: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("level lock still held after a failed hook")
	}
}

// The hook runs before the change is decided: a refused weakening has already
// had its request journaled by it, so the refusal is accounted for.
func TestChangeLevel_OnLockedRunsBeforeTheChangeIsDecided(t *testing.T) {
	w := newWorld(t)
	calls := 0
	_, err := w.s.ChangeLevel(context.Background(), LevelChange{Org: org, To: LevelOrg, Actor: "admin",
		OnLocked: func(context.Context) error { calls++; return nil }}, w.st)
	if !errors.Is(err, ErrWeakeningNotConfirmed) {
		t.Fatalf("err %v, want ErrWeakeningNotConfirmed", err)
	}
	if calls != 1 {
		t.Fatalf("hook ran %d times on a refused weakening, want 1", calls)
	}
}
