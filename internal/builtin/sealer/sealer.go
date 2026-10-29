package sealer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/entire-vc/evc-keep/pkg/secret"
)

// Ref identifies one secret version inside the built-in provider.
type Ref struct {
	Store    Scope // owner scope of the store holding the secret
	SecretID string
	Name     string
	Version  string
}

func (r Ref) validate() error {
	if err := r.Store.validate(); err != nil {
		return err
	}
	if r.SecretID == "" || r.Version == "" {
		return ErrInvalidRef
	}
	return nil
}

// ErrInvalidRef is returned for a Ref missing its secret id or version.
var ErrInvalidRef = errors.New("sealer: invalid ref")

// Envelope is what the database stores for one secret version. None of its
// fields is secret: WrappedDEK and Ciphertext authenticate only under keys
// that never leave the sealer.
type Envelope struct {
	KEKID      string // the KEK that wraps WrappedDEK
	WrappedDEK []byte
	Ciphertext []byte
}

// Event is an audit record of a key-hierarchy operation. It carries names,
// levels and counts, never key material or values.
type Event struct {
	RequestID string // the request a key-level outcome belongs to, empty if it has none
	Action    string // key_level_changed, key_level_change_denied, key_level_change_failed, kek_purged
	Org       string
	Actor     string
	SecretID  string // blocking envelope, only for a failed rewrap callback
	Version   string
	From, To  Level
	Rewrapped int
	Unchanged int
	Retired   int
	Purged    int
	Reason    string
}

// Auditor receives key-hierarchy events; in the server it is the journal.
type Auditor interface{ Record(Event) }

// EnvelopeStore is the persistence of envelopes, scoped to one organisation.
type EnvelopeStore interface {
	// Each calls fn for every envelope of org and stops at the first error.
	Each(ctx context.Context, org string, fn func(Ref, Envelope) error) error
	// Rewrap calls fn for every envelope of org and stores the envelope fn
	// returns in place of the old one. It stops at the first error; the
	// envelopes already replaced stay replaced.
	Rewrap(ctx context.Context, org string, fn func(Ref, Envelope) (Envelope, error)) error
}

// LockBound may be implemented by the EnvelopeStore passed to
// [Sealer.ChangeLevel]. ChangeLevel calls BindToLock with the Store that
// [LevelStore.Lock] returned and scans and rewrites envelopes through the
// EnvelopeStore it gets back, so that work runs on the connection the level
// lock is held on instead of borrowing another one.
type LockBound interface {
	BindToLock(locked Store) EnvelopeStore
}

// Errors of level changes.
var (
	ErrWeakeningNotConfirmed = errors.New("sealer: key level change weakens isolation and was not confirmed")
	ErrNoActor               = errors.New("sealer: key level change needs an actor")
	ErrUnknownKEK            = errors.New("sealer: envelope refers to an unknown key")
	ErrRewrapIncomplete      = errors.New("sealer: rewrap_incomplete")
)

// Sealer seals and opens values of the built-in provider. Both its KEK
// records and its organisations' key levels are persisted through store
// (see Store) — nothing here lives only in process memory, so a restart or
// a second server process sharing the same database sees the same state.
type Sealer struct {
	root  RootKey
	audit Auditor
	store Store
}

// New returns a Sealer over root, persisting its KEK records and key levels
// to store. audit and store must not be nil.
func New(root RootKey, audit Auditor, store Store) *Sealer {
	return &Sealer{root: root, audit: audit, store: store}
}

// WithStore returns a Sealer identical to s but persisting its KEK records
// and key levels through st instead of s's own store — root and audit are
// shared. A caller that will read the level via Seal and then persist the
// resulting Envelope (Provider.Write, Provider.FingerprintKey) uses this to
// scope one such call to a store bound to a connection it already holds a
// lock on (see the caller's own doc comment for why running Seal's Level/
// KEK lookups through a second, separately pool-borrowed connection —
// rather than the one already doing the locking and the persisting — could
// exhaust the pool under concurrency), instead of each of Seal's own store
// calls borrowing a fresh connection of its own.
func (s *Sealer) WithStore(st Store) *Sealer {
	return &Sealer{root: s.root, audit: s.audit, store: st}
}

// Level returns the current key level of org, or DefaultLevel if none was
// ever set.
func (s *Sealer) Level(ctx context.Context, org string) (Level, error) {
	return s.store.Level(ctx, org)
}

// Seal encrypts v under a fresh DEK and wraps the DEK with the KEK of the
// store's key domain. Seal only reads the level and computes the envelope —
// it does not persist anything and so does not itself take any lock; a
// caller that will store the result must hold the org's key-level lock
// (LevelStore.Lock's shared side) for the whole read-level-then-persist
// sequence, not only around this call — see ChangeLevel's doc comment for
// the race this closes, and WithStore's for how to do this without an
// extra pool connection.
func (s *Sealer) Seal(ctx context.Context, ref Ref, v secret.Value) (Envelope, error) {
	if err := ref.validate(); err != nil {
		return Envelope{}, err
	}
	level, err := s.store.Level(ctx, ref.Store.Org)
	if err != nil {
		return Envelope{}, err
	}
	k, kb, err := s.activeKEK(ctx, Domain(ref.Store, level))
	if err != nil {
		return Envelope{}, err
	}
	defer wipe(kb)

	dek, err := randomKey()
	if err != nil {
		return Envelope{}, err
	}
	defer wipe(dek)
	da, err := newAEAD(dek)
	if err != nil {
		return Envelope{}, err
	}
	var ct []byte
	secret.Expose(v, func(b []byte) { ct, err = seal(da, b, valueAAD(ref)) })
	if err != nil {
		return Envelope{}, err
	}
	ka, err := newAEAD(kb)
	if err != nil {
		return Envelope{}, err
	}
	w, err := seal(ka, dek, dekAAD(ref, k.ID))
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{KEKID: k.ID, WrappedDEK: w, Ciphertext: ct}, nil
}

// Open decrypts an envelope sealed for ref.
func (s *Sealer) Open(ctx context.Context, ref Ref, e Envelope) (secret.Value, error) {
	if err := ref.validate(); err != nil {
		return secret.Value{}, err
	}
	dek, err := s.unwrapDEK(ctx, ref, e)
	if err != nil {
		return secret.Value{}, err
	}
	defer wipe(dek)
	da, err := newAEAD(dek)
	if err != nil {
		return secret.Value{}, err
	}
	p, err := open(da, e.Ciphertext, valueAAD(ref))
	if err != nil {
		return secret.Value{}, err
	}
	defer wipe(p)
	return secret.New(p), nil
}

// LevelChange asks to move an organisation to another key level. The caller
// (policy + orchestrator) has already checked that Actor is an administrator
// of Org; the sealer records who asked.
type LevelChange struct {
	Org   string
	To    Level
	Actor string
	// RequestID names the request the change answers; every event of the
	// change carries it so the journal can pair outcome and request.
	RequestID string
	// ConfirmWeakening must be set to move to a coarser level: it shares
	// KEKs among more stores and so weakens isolation.
	ConfirmWeakening bool
	// OnLocked, when set, is called once under the level lock, before the
	// change is decided or anything is written. It is where a caller
	// journals the request of the change, so the request exists exactly
	// while the change can run: a process that stalls before the lock has
	// written nothing for a reconcile pass to close. Its context carries
	// the OnLockedTimeout deadline. An error ends the change before it
	// touches anything and is returned wrapped in ErrOnLocked; nothing is
	// audited for it, the hook owns its own record. Nil means no hook. The
	// hook must not call ChangeLevel or take the level lock of the same org:
	// it would wait on the lock it runs under until its deadline.
	OnLocked func(ctx context.Context) error
}

// OnLockedTimeout bounds LevelChange.OnLocked: the hook runs while the level
// lock is held, so a slow one must not hold up writers behind it.
const OnLockedTimeout = 15 * time.Second

// LockContexter is implemented by a Store whose Lock holds a connection: it
// returns ctx carrying that connection, so an OnLocked hook can run its own
// statements on the connection the lock is held on instead of borrowing
// another one from the pool while writers queue behind the lock with the
// rest of it.
type LockContexter interface {
	WithLockConn(ctx context.Context) context.Context
}

// ErrOnLocked wraps what a LevelChange.OnLocked hook returned.
var ErrOnLocked = errors.New("sealer: change level: request hook failed")

// ChangeResult reports what a level change did.
type ChangeResult struct {
	From, To  Level
	Rewrapped int // DEKs moved to the KEK of their new domain
	Unchanged int // DEKs already under the right KEK
	Retired   int // KEKs no longer used for new DEKs
}

// ChangeLevel switches org to c.To and re-wraps every DEK under the KEK of
// its new domain. Value ciphertexts are not touched.
//
// The whole operation — reading the current level, deciding, persisting the
// new one, re-wrapping every existing DEK and retiring the KEKs the new
// level no longer uses — runs under one exclusive LevelStore.Lock for org,
// held from before the first read to after the last write. Earlier this
// lock (via the now-removed WithLevelLock) covered only the level row's own
// read-decide-write; Rewrap and retire ran after it was released. That let
// two ChangeLevel calls for the same org interleave their re-wrapping, and
// let a concurrent Seal read the level, race Rewrap's snapshot, and commit
// its envelope under the old (possibly now-retired, possibly shared) KEK
// with nothing left to ever re-wrap it — silently reintroducing exactly the
// shared-KEK exposure a strengthening ChangeLevel was meant to close. Seal's
// callers close the other half of this by holding the lock's shared side
// (LevelStore.Lock with exclusive=false, or an equivalent transaction-scoped
// lock on the same key — see Provider.Write's doc comment) for their whole
// read-level-then-persist sequence.
//
// New seals use the new level as soon as this call starts (i.e. as soon as
// it acquires the lock — a concurrent Seal either finished, and is visible
// to Rewrap's snapshot, before that, or cannot proceed until this call
// releases the lock). If the store fails half-way, every envelope stays
// readable (each names its own KEK), nothing is retired, and running the
// same change again completes it.
//
// Every Level/SetLevel/KEKStore call this makes (the initial read and
// write, and activeKEK/Get/retire's ActiveList/Retire during and after
// Rewrap) runs through the connection Lock's return is already bound to,
// not a separately pool-borrowed one — see LevelStore.Lock's doc comment.
// The envelope scan and updates do too when st implements [LockBound]: it is
// then rebound to the Store Lock returned, so the whole operation costs the
// one connection the lock already holds. An EnvelopeStore that does not
// (an in-memory test double) is used as given. Without the binding, Rewrap
// borrowed one more connection from the pool while writers queued behind the
// lock held the rest, and the writers could not finish until ChangeLevel
// did: a deadlock that only a context deadline ended.
func (s *Sealer) ChangeLevel(ctx context.Context, c LevelChange, st EnvelopeStore) (ChangeResult, error) {
	if !c.To.Valid() {
		s.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_denied", Org: c.Org, Actor: c.Actor, To: c.To, Reason: "invalid_level"})
		return ChangeResult{}, ErrInvalidLevel
	}
	if c.Org == "" {
		s.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_denied", Org: c.Org, Actor: c.Actor, To: c.To, Reason: "invalid_scope"})
		return ChangeResult{}, ErrInvalidScope
	}
	if c.Actor == "" {
		s.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_denied", Org: c.Org, Actor: c.Actor, To: c.To, Reason: "no_actor"})
		return ChangeResult{}, ErrNoActor
	}

	locked, release, err := s.store.Lock(ctx, c.Org, true)
	if err != nil {
		s.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_failed", Org: c.Org, Actor: c.Actor, To: c.To, Reason: "lock_failed"})
		return ChangeResult{}, fmt.Errorf("sealer: change level: lock: %w", err)
	}
	defer func() { _ = release(ctx) }()
	if c.OnLocked != nil {
		hctx, cancel := context.WithTimeout(ctx, OnLockedTimeout)
		if lc, ok := locked.(LockContexter); ok {
			hctx = lc.WithLockConn(hctx)
		}
		herr := c.OnLocked(hctx)
		cancel()
		if herr != nil {
			// The hook's own text is not forwarded: it comes from outside
			// the sealer and may name whatever its backend echoed.
			return ChangeResult{}, ErrOnLocked
		}
	}
	ls := s.WithStore(locked)
	if lb, ok := st.(LockBound); ok {
		st = lb.BindToLock(locked)
	}

	from, err := locked.Level(ctx, c.Org)
	if err != nil {
		s.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_failed", Org: c.Org, Actor: c.Actor, To: c.To, Reason: "level_read_failed"})
		return ChangeResult{}, fmt.Errorf("sealer: change level: %w", err)
	}
	if from.Weakens(c.To) && !c.ConfirmWeakening {
		s.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_denied", Org: c.Org, Actor: c.Actor, From: from, To: c.To, Reason: "weakening_not_confirmed"})
		return ChangeResult{From: from, To: c.To}, ErrWeakeningNotConfirmed
	}
	if err := locked.SetLevel(ctx, c.Org, c.To, c.Actor); err != nil {
		s.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_failed", Org: c.Org, Actor: c.Actor, From: from, To: c.To, Reason: "level_write_failed"})
		return ChangeResult{}, fmt.Errorf("sealer: change level: %w", err)
	}

	res := ChangeResult{From: from, To: c.To}
	var secretID, version string
	err = st.Rewrap(ctx, c.Org, func(ref Ref, e Envelope) (out Envelope, callbackErr error) {
		// Capture only the failed callback's identifiers. A scan/update
		// failure outside the callback must not blame a healthy envelope.
		defer func() {
			if callbackErr != nil {
				secretID, version = ref.SecretID, ref.Version
			}
		}()
		if ref.Store.Org != c.Org {
			return e, ErrInvalidScope
		}
		t, tb, err := ls.activeKEK(ctx, Domain(ref.Store, c.To))
		if err != nil {
			return e, err
		}
		defer wipe(tb)
		dek, err := ls.unwrapDEK(ctx, ref, e)
		if err != nil {
			return e, err
		}
		defer wipe(dek)
		// Even an already-current KEK must authenticate the wrapped DEK:
		// otherwise a retry silently accepts a damaged/substituted row.
		if e.KEKID == t.ID {
			res.Unchanged++
			return e, nil
		}
		ta, err := newAEAD(tb)
		if err != nil {
			return e, err
		}
		w, err := seal(ta, dek, dekAAD(ref, t.ID))
		if err != nil {
			return e, err
		}
		res.Rewrapped++
		return Envelope{KEKID: t.ID, WrappedDEK: w, Ciphertext: e.Ciphertext}, nil
	})
	if err != nil {
		s.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_failed", Org: c.Org, Actor: c.Actor, SecretID: secretID, Version: version, From: from, To: c.To, Rewrapped: res.Rewrapped, Unchanged: res.Unchanged, Reason: "rewrap_incomplete"})
		return res, fmt.Errorf("%w: secret_id=%q version=%q: %w", ErrRewrapIncomplete, secretID, version, err)
	}

	retired, err := ls.retire(ctx, c.Org, c.To)
	if err != nil {
		s.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_change_failed", Org: c.Org, Actor: c.Actor, From: from, To: c.To, Rewrapped: res.Rewrapped, Unchanged: res.Unchanged, Reason: "retire_incomplete"})
		return res, fmt.Errorf("sealer: key level change incomplete (retire), run it again: %w", err)
	}
	res.Retired = retired
	s.audit.Record(Event{RequestID: c.RequestID, Action: "key_level_changed", Org: c.Org, Actor: c.Actor, From: from, To: c.To, Rewrapped: res.Rewrapped, Unchanged: res.Unchanged, Retired: res.Retired})
	return res, nil
}

// Purge destroys the retired KEKs of org that no envelope refers to any
// more. Destroying a KEK is crypto-erasure of whatever it still wrapped, so
// it scans the store first and keeps every referenced key.
func (s *Sealer) Purge(ctx context.Context, org, actor string, st EnvelopeStore) (int, error) {
	failed := func(reason string, err error) (int, error) {
		s.audit.Record(Event{Action: "kek_purge_failed", Org: org, Actor: actor, Reason: reason})
		return 0, err
	}
	if actor == "" {
		return failed("no_actor", ErrNoActor)
	}
	if org == "" {
		return failed("invalid_scope", ErrInvalidScope)
	}
	used := map[string]bool{}
	if err := st.Each(ctx, org, func(_ Ref, e Envelope) error { used[e.KEKID] = true; return nil }); err != nil {
		return failed("scan_failed", err)
	}
	retired, err := s.store.RetiredList(ctx, org)
	if err != nil {
		return failed("list_failed", err)
	}
	var toPurge []string
	for _, k := range retired {
		if !k.Domain.PKI && !used[k.ID] {
			toPurge = append(toPurge, k.ID)
		}
	}
	if len(toPurge) > 0 {
		if err := s.store.Purge(ctx, org, toPurge); err != nil {
			return failed("purge_failed", err)
		}
	}
	n := len(toPurge)
	s.audit.Record(Event{Action: "kek_purged", Org: org, Actor: actor, Purged: n})
	return n, nil
}

// retire marks retired every KEK currently active for org whose domain does
// not exist at level l any more — the KEKs ChangeLevel just moved every DEK
// away from.
func (s *Sealer) retire(ctx context.Context, org string, l Level) (int, error) {
	actives, err := s.store.ActiveList(ctx, org)
	if err != nil {
		return 0, err
	}
	var toRetire []string
	for _, k := range actives {
		if Domain(k.Domain, l) != k.Domain {
			toRetire = append(toRetire, k.ID)
		}
	}
	if len(toRetire) == 0 {
		return 0, nil
	}
	if err := s.store.Retire(ctx, org, toRetire); err != nil {
		return 0, err
	}
	return len(toRetire), nil
}

// activeKEK returns the KEK that wraps new DEKs of domain d, creating it on
// first use, together with its plaintext bytes (caller wipes them).
func (s *Sealer) activeKEK(ctx context.Context, d Scope) (KEKRecord, []byte, error) {
	domainKey := d.key()
	rec, err := s.store.ActiveFor(ctx, d.Org, domainKey)
	switch {
	case err == nil:
		return s.unwrapVerifiedKEK(rec, d)
	case errors.Is(err, ErrNoActiveKEK):
		// fall through to create one below
	default:
		return KEKRecord{}, nil, err
	}

	b, err := randomKey()
	if err != nil {
		return KEKRecord{}, nil, err
	}
	var idb [16]byte
	if _, err := rand.Read(idb[:]); err != nil {
		wipe(b)
		return KEKRecord{}, nil, err
	}
	want := KEKRecord{ID: "kek_" + hex.EncodeToString(idb[:]), Org: d.Org, Domain: d, RootKeyID: s.root.ID()}
	wrapped, err := s.root.Wrap(b, kekAAD(want.ID, want.Org, domainKey, want.RootKeyID))
	if err != nil {
		wipe(b)
		return KEKRecord{}, nil, err
	}
	want.Wrapped = wrapped

	rec, err = s.store.Create(ctx, domainKey, want)
	if err != nil {
		wipe(b)
		return KEKRecord{}, nil, err
	}
	if rec.ID != want.ID {
		// A concurrent caller created the active KEK for this domain first;
		// want's bytes were never persisted, unwrap the winner instead.
		wipe(b)
		return s.unwrapVerifiedKEK(rec, d)
	}
	return rec, b, nil
}

// unwrapVerifiedKEK unwraps rec after checking it is actually the KEK of
// domain d — not just a record the store happened to hand back when asked
// for d's domain key. domain_key is a store-level index for lookup only;
// it is never itself authenticated by the crypto (kekAAD binds to rec.Org
// and rec.Domain, which it recomputes from those fields, not from whatever
// index the store used to find the row — see kekAAD), so a store bug or a
// corrupted domain_key column could otherwise hand back a KEK belonging to
// a different domain and Seal would use it without error, sharing that KEK
// across two stores that should be isolated. This check is the boundary
// that catches that before any key bytes are unwrapped for use.
func (s *Sealer) unwrapVerifiedKEK(rec KEKRecord, d Scope) (KEKRecord, []byte, error) {
	if rec.Org != d.Org || rec.Domain != d {
		return KEKRecord{}, nil, fmt.Errorf("%w: active kek for %s does not match its own domain", ErrUnknownKEK, d.key())
	}
	b, err := s.unwrapKEK(rec)
	return rec, b, err
}

func (s *Sealer) unwrapKEK(rec KEKRecord) ([]byte, error) {
	if rec.RootKeyID != s.root.ID() {
		return nil, ErrUnwrap
	}
	return s.root.Unwrap(rec.Wrapped, kekAAD(rec.ID, rec.Org, rec.Domain.key(), rec.RootKeyID))
}

func (s *Sealer) unwrapDEK(ctx context.Context, ref Ref, e Envelope) ([]byte, error) {
	rec, err := s.store.Get(ctx, ref.Store.Org, e.KEKID)
	switch {
	case errors.Is(err, ErrKEKNotFound):
		return nil, ErrUnknownKEK
	case err != nil:
		return nil, fmt.Errorf("sealer: get kek: %w", err)
	}
	kb, err := s.unwrapKEK(rec)
	if err != nil {
		return nil, err
	}
	defer wipe(kb)
	ka, err := newAEAD(kb)
	if err != nil {
		return nil, err
	}
	return open(ka, e.WrappedDEK, dekAAD(ref, e.KEKID))
}

// AAD layouts. The KEK is bound to its org and domain, the DEK to the exact
// secret version and the KEK that wraps it, the value to the secret version.
func kekAAD(id, org, domainKey, rootID string) []byte {
	return aad("keep/kek/v1", org, domainKey, id, rootID)
}

func dekAAD(r Ref, kekID string) []byte {
	return aad("keep/dek/v1", r.Store.key(), r.SecretID, r.Version, kekID)
}

func valueAAD(r Ref) []byte {
	return aad("keep/value/v1", r.Store.Org, r.SecretID, r.Name, r.Version)
}
