package rotation

import (
	"context"
	"errors"
	"slices"

	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider"
	prot "github.com/entire-vc/evc-keep/pkg/rotation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrPrepare and ErrRevoke are the only errors the provider adapters return:
// a collaborator's error text is never forwarded, it may sit next to a value.
var (
	ErrPrepare = errors.New("rotation: provider prepare failed")
	ErrRevoke  = errors.New("rotation: provider revoke failed")
)

// Target is where one secret's versions are stored and what the provider
// issues the key for. All three are metadata.
type Target struct {
	Store   provider.Provider
	Ref     provider.Ref // Version empty: the secret as a whole
	Subject string
}

// Resolver finds the target of a secret.
type Resolver func(ctx context.Context, ref Ref) (Target, error)

// ProviderDeps are what the adapters over a RotationProvider need.
type ProviderDeps struct {
	Provider prot.RotationProvider
	Resolve  Resolver
	Ledger   *Ledger
	// Incident records an original key that was not revoked because it was not
	// known. Required with a DualKey provider.
	Incident Incident
	// FingerprintKey returns the key the fingerprint of a new version is
	// computed with. It must return a fresh copy the caller owns: the adapter
	// wipes it after use.
	FingerprintKey func(ctx context.Context) (fingerprint.Key, error)
}

// ProviderVersions is the Versions of a RotationProvider: it issues the key,
// seals the value as a new version of the secret and records which key stands
// behind it. Without DualKey the sealing comes first and the run is forward
// only (see ForwardOnly).
type ProviderVersions struct{ d ProviderDeps }

func NewProviderVersions(d ProviderDeps) *ProviderVersions { return &ProviderVersions{d: d} }

// ForwardOnly is true when the provider cannot keep the old key valid. The
// engine reads it: a failed layout is retried, never rolled back.
func (v *ProviderVersions) ForwardOnly() bool { return !v.d.Provider.Capabilities().DualKey }

// Prepare issues and seals the new version. It is idempotent per runID: a
// resumed run gets the recorded version back and the provider is not asked
// again, which matters for a forward-only provider, where a second Issue
// would end the key the first one made.
func (v *ProviderVersions) Prepare(ctx context.Context, ref Ref, runID uuid.UUID) (Version, error) {
	if got, ok, err := v.d.Ledger.byRun(ctx, runID); err != nil {
		return Version{}, ErrPrepare
	} else if ok {
		if got.ref != ref {
			return Version{}, ErrPrepare
		}
		return Version{Old: got.old, New: got.new, Fingerprint: got.fp, Length: got.length}, nil
	}
	// A DualKey run may end with an original key it cannot name; the incident
	// that says so must be possible before anything is issued.
	if v.d.Provider.Capabilities().DualKey && v.d.Incident == nil {
		return Version{}, ErrPrepare
	}
	t, err := v.d.Resolve(ctx, ref)
	if err != nil {
		return Version{}, ErrPrepare
	}
	old := ""
	switch m, err := t.Store.Version(ctx, t.Ref); {
	case err == nil:
		old = m.Version
	case !errors.Is(err, provider.ErrNotFound):
		return Version{}, ErrPrepare
	}
	// Everything that can fail without a value happens before Issue: with a
	// forward-only provider Issue ends the old key, and after it a failure
	// leaves nothing but the new value.
	key, err := v.d.FingerprintKey(ctx)
	if err != nil {
		return Version{}, ErrPrepare
	}
	defer key.Wipe()
	// The original key is read before Issue: after it, a provider that keeps two
	// keys may name the new one. An error or an unknown key is not a failure of
	// the run, it only means the original key will not be revoked.
	orig := ""
	if v.d.Provider.Capabilities().DualKey {
		if id, ok, err := v.d.Provider.Current(ctx, t.Subject); err == nil && ok && prot.ValidKeyID(id) {
			orig = id
		}
	}
	// Issue cannot be undone and is asked once per run. The intent is durable
	// before it: a run that dies between Issue and the ledger row finds the
	// intent on replay and does not ask again.
	if fresh, err := v.d.Ledger.intend(ctx, ref, runID); err != nil || !fresh {
		return Version{}, ErrPrepare
	}
	iss, err := v.d.Provider.Issue(ctx, prot.IssueRequest{Subject: t.Subject, RunID: runID})
	defer iss.Value.Wipe()
	if err != nil {
		return Version{}, ErrPrepare
	}
	if !prot.ValidKeyID(iss.KeyID) || iss.Value.IsZero() {
		v.rollback(ctx, ref, runID, iss.KeyID)
		return Version{}, ErrPrepare
	}
	fp, err := fingerprint.Compute(key, iss.Value)
	if err != nil {
		v.rollback(ctx, ref, runID, iss.KeyID)
		return Version{}, ErrPrepare
	}
	// Sealing next: with a forward-only provider the old key is already gone
	// and this value is the only copy of the new one.
	meta, err := t.Store.Write(ctx, t.Ref, iss.Value)
	if err != nil || !validVersion(meta.Version) {
		v.rollback(ctx, ref, runID, iss.KeyID)
		return Version{}, ErrPrepare
	}
	rec := keyRow{ref: ref, runID: runID, keyID: iss.KeyID, old: old, new: meta.Version, fp: fp, orig: orig, length: iss.Value.Len()}
	if err := v.d.Ledger.put(ctx, rec); err != nil {
		// The insert may have committed before the error reached us. Ending the
		// key then would leave a recorded version whose key is dead, so the row
		// is read back first; if that read fails too the state is unknown and
		// the key is kept (an unrecorded key is cheaper than a dead recorded one).
		got, ok, rerr := v.d.Ledger.byRun(context.WithoutCancel(ctx), runID)
		switch {
		case rerr != nil:
			return Version{}, ErrPrepare
		case ok && got.keyID == iss.KeyID:
			return Version{Old: got.old, New: got.new, Fingerprint: got.fp, Length: got.length}, nil
		}
		v.rollback(ctx, ref, runID, iss.KeyID)
		return Version{}, ErrPrepare
	}
	return Version{Old: old, New: meta.Version, Fingerprint: fp, Length: iss.Value.Len()}, nil
}

// Adopt checks a version a human entered and returns the write that records it
// under the run: the ledger row the revoke step reads. No key was issued, so
// the key id is a fresh label that names nothing at the provider. Nothing is
// written here; the caller runs the write in the transaction that creates the
// run. Idempotent per runID.
func (v *ProviderVersions) Adopt(ctx context.Context, ref Ref, runID uuid.UUID, ver Version) (AdoptWrite, error) {
	got, ok, err := v.d.Ledger.byRun(ctx, runID)
	if err != nil {
		return nil, ErrPrepare
	}
	if ok {
		if got.ref != ref || got.new != ver.New {
			return nil, ErrPrepare
		}
		return func(context.Context, pgx.Tx) error { return nil }, nil
	}
	if v.d.Provider.Capabilities().DualKey && v.d.Incident == nil {
		return nil, ErrPrepare
	}
	t, err := v.d.Resolve(ctx, ref)
	if err != nil {
		return nil, ErrPrepare
	}
	orig := ""
	if v.d.Provider.Capabilities().DualKey {
		if id, ok, err := v.d.Provider.Current(ctx, t.Subject); err == nil && ok && prot.ValidKeyID(id) {
			orig = id
		}
	}
	rec := keyRow{ref: ref, runID: runID, keyID: uuid.NewString(), old: ver.Old, new: ver.New, fp: ver.Fingerprint, orig: orig}
	return func(ctx context.Context, tx pgx.Tx) error {
		if err := v.d.Ledger.putTx(ctx, tx, rec); err != nil {
			return ErrPrepare
		}
		return nil
	}, nil
}

// rollback ends the new key when the provider keeps the old one valid, and
// confirms it with Check like every other revoke. A key that is not confirmed
// ended is an incident of its own. A forward-only provider has no way back: the
// failure is an incident.
func (v *ProviderVersions) rollback(ctx context.Context, ref Ref, runID uuid.UUID, keyID string) {
	if !v.d.Provider.Capabilities().DualKey {
		return
	}
	rctx := context.WithoutCancel(ctx)
	if err := v.d.Provider.Revoke(rctx, keyID); err == nil {
		if st, err := v.d.Provider.Check(rctx, keyID); err == nil && !st.Active {
			return
		}
	}
	_ = v.d.Incident.Open(rctx, IncidentRecord{Ref: ref, RunID: runID, Class: ClassRollbackUnconfirmed})
}

// ProviderRevoker is the Revoker of a RotationProvider: it ends the old key
// and disables the old version of the secret.
type ProviderRevoker struct{ d ProviderDeps }

func NewProviderRevoker(d ProviderDeps) *ProviderRevoker { return &ProviderRevoker{d: d} }

// Revoke is idempotent per (runID, oldVersion). It acts only for the run that
// made the current new version and for the version that run replaced.
func (r *ProviderRevoker) Revoke(ctx context.Context, ref Ref, runID uuid.UUID, oldVersion string) error {
	rec, ok, err := r.d.Ledger.byRun(ctx, runID)
	if err != nil || !ok || rec.ref != ref || rec.old != oldVersion || oldVersion == "" {
		return ErrRevoke
	}
	t, err := r.d.Resolve(ctx, ref)
	if err != nil {
		return ErrRevoke
	}
	// Nothing known to revoke: never revoke what is not known. The old version
	// is still disabled, and the run says so (after the disable, so the journal
	// names the last thing that went wrong).
	unknown := false
	// Forward-only: the old key ended when the new one was issued, there is
	// nothing to revoke at the provider.
	if r.d.Provider.Capabilities().DualKey {
		oldKey, _, err := r.d.Ledger.keyOf(ctx, ref, oldVersion)
		if err != nil {
			return ErrRevoke
		}
		// The keys behind the old version: the one the provider named when the
		// run began (the first rotation of a secret has no ledger row), then the
		// one a run recorded. The new key is never among them: two active keys
		// make Current ambiguous, and Issue may hand the same key back on a resume.
		var keys []string
		for _, k := range []string{rec.orig, oldKey} {
			if k != "" && k != rec.keyID && !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
		// An unknown original key is an incident even when a ledger key can still
		// be revoked: Current is what the run could not learn.
		unknown = rec.orig == "" || rec.orig == rec.keyID
		for _, k := range keys {
			if err := r.d.Provider.Revoke(ctx, k); err != nil {
				return ErrRevoke
			}
			if st, err := r.d.Provider.Check(ctx, k); err != nil || st.Active {
				return ErrRevoke
			}
		}
	}
	dis := t.Ref
	dis.Version = oldVersion
	if err := t.Store.Disable(ctx, dis); err != nil && !errors.Is(err, provider.ErrNotFound) {
		return ErrRevoke
	}
	if unknown {
		if err := r.d.Incident.Open(ctx, IncidentRecord{Ref: ref, RunID: runID, Class: ClassOriginalKeyUnknown}); err != nil {
			return ErrRevoke
		}
	}
	return nil
}

// Ledger records which key stands behind which version. Metadata only.
type Ledger struct {
	pool *pgxpool.Pool
	// afterPut, set only by tests, fails put after the row is committed.
	afterPut func() error
	// beforePut, set only by tests, fails put before the row is written: the
	// run died after the value was sealed.
	beforePut func() error
}

func NewLedger(pool *pgxpool.Pool) *Ledger { return &Ledger{pool: pool} }

type keyRow struct {
	ref          Ref
	runID        uuid.UUID
	keyID        string
	old, new, fp string
	orig         string // the key behind old when the run began; empty: unknown
	length       int    // byte length of the new value; 0 unknown
}

// intend records that the run is about to ask the provider for a key. fresh is
// false when the run already did: the outcome of that Issue is unknown.
func (l *Ledger) intend(ctx context.Context, ref Ref, runID uuid.UUID) (bool, error) {
	tag, err := l.pool.Exec(ctx, `INSERT INTO rotation_intents(run_id, org_id, secret_id) VALUES ($1,$2,$3) ON CONFLICT (run_id) DO NOTHING`,
		runID, ref.OrgID, ref.SecretID)
	return err == nil && tag.RowsAffected() == 1, err
}

func (l *Ledger) put(ctx context.Context, k keyRow) error {
	if l.beforePut != nil {
		if err := l.beforePut(); err != nil {
			return err
		}
	}
	_, err := l.pool.Exec(ctx, `INSERT INTO rotation_keys(run_id, org_id, secret_id, key_id, old_version, new_version, fingerprint, original_key_id, new_length)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (run_id) DO NOTHING`,
		k.runID, k.ref.OrgID, k.ref.SecretID, k.keyID, k.old, k.new, k.fp, k.orig, k.length)
	if err == nil && l.afterPut != nil {
		err = l.afterPut()
	}
	return err
}

// putTx records the row inside a transaction, so that it is taken back with it.
func (l *Ledger) putTx(ctx context.Context, tx pgx.Tx, k keyRow) error {
	_, err := tx.Exec(ctx, `INSERT INTO rotation_keys(run_id, org_id, secret_id, key_id, old_version, new_version, fingerprint, original_key_id, new_length)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (run_id) DO NOTHING`,
		k.runID, k.ref.OrgID, k.ref.SecretID, k.keyID, k.old, k.new, k.fp, k.orig, k.length)
	return err
}

func (l *Ledger) byRun(ctx context.Context, runID uuid.UUID) (keyRow, bool, error) {
	k := keyRow{runID: runID}
	err := l.pool.QueryRow(ctx, `SELECT org_id, secret_id, key_id, old_version, new_version, fingerprint, original_key_id, new_length FROM rotation_keys WHERE run_id=$1`, runID).
		Scan(&k.ref.OrgID, &k.ref.SecretID, &k.keyID, &k.old, &k.new, &k.fp, &k.orig, &k.length)
	if errors.Is(err, pgx.ErrNoRows) {
		return keyRow{}, false, nil
	}
	return k, err == nil, err
}

// keyOf is the key behind a version of a secret, if a run recorded one.
func (l *Ledger) keyOf(ctx context.Context, ref Ref, version string) (string, bool, error) {
	var id string
	err := l.pool.QueryRow(ctx, `SELECT key_id FROM rotation_keys WHERE org_id=$1 AND secret_id=$2 AND new_version=$3 ORDER BY created_at DESC LIMIT 1`,
		ref.OrgID, ref.SecretID, version).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return id, err == nil, err
}
