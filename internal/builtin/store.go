// Package builtin is Keep's built-in storage provider: pkg/provider.Provider
// implemented over internal/builtin/sealer, persisted to PostgreSQL. Unlike
// external providers (ADR-001 §3.3: they run inside the runner, the server
// never calls them), the built-in provider's crypto runs on the server —
// its plaintext handling is confined to this package and to sealer, which
// only this package may import (see .golangci.yml, rule "sealer").
package builtin

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
)

// errNotFound is returned by the row-level lookups below for "no such row";
// each caller in provider.go / fpkey.go turns it into the right
// pkg/provider error class for its own operation (ErrNotFound, or a
// fallback to ErrDisabled when the id exists but has no active version).
var errNotFound = errors.New("builtin: not found")

// dbtx is the query surface every store method below runs its work
// through — implemented by both *pgxpool.Pool (a fresh, independently
// pool-borrowed connection per call, store's default) and pgx.Tx (a single
// already-open transaction). store.withTx swaps in a tx so a whole
// multi-statement, lock-holding operation can run on the one connection
// that transaction already owns instead of each call borrowing its own —
// see withTx's doc comment for the pool-exhaustion this closes.
type dbtx interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// store is the PostgreSQL persistence behind the built-in provider: the KEK
// records of sealer's key hierarchy (it implements sealer.KEKStore and
// sealer.EnvelopeStore) and the envelope of every secret version, including
// the fingerprint key each store seals under a reserved secret id (fpkey.go).
type store struct {
	pool *pgxpool.Pool // needed only for Lock's own dedicated connection
	db   dbtx          // where every query above actually runs; pool by default
}

// NewKeyStore returns PostgreSQL persistence for the shared key hierarchy.
func NewKeyStore(pool *pgxpool.Pool) sealer.Store { return newStore(pool) }

// NewTransactionKeyStore binds read-only cryptographic lookups to a transaction
// already held by the caller. It must not be used for operations taking their
// own connection or transaction, such as administrative key-level changes.
func NewTransactionKeyStore(tx pgx.Tx) sealer.Store { return &store{db: tx} }

func newStore(pool *pgxpool.Pool) *store { return &store{pool: pool, db: pool} }

// withTx returns a store whose queries all run inside tx instead of each
// borrowing its own connection from the pool. Provider.Write and
// Provider.FingerprintKey use this to keep their whole read-level,
// take-the-org-lock, seal, persist sequence to the one connection their
// transaction already holds — before this, that sequence could need three
// simultaneous pool connections (the lock, the transaction, and whichever
// query happened to run inside Seal), so a handful of concurrent callers
// could exhaust a modestly-sized pool and hang everyone waiting on it —
// see TestWrite_DoesNotExhaustPool, confirmed to fail without this fix
// under a small pool.
func (s *store) withTx(tx pgx.Tx) *store { return &store{pool: s.pool, db: tx} }

// ── sealer.KEKStore ─────────────────────────────────────────────────────

type rowScanner interface{ Scan(dest ...any) error }

func scanKEK(row rowScanner) (sealer.KEKRecord, error) {
	var rec sealer.KEKRecord
	var domainKey string
	err := row.Scan(&rec.ID, &rec.Org, &rec.Domain.Org, &rec.Domain.Workspace, &rec.Domain.Project, &rec.Domain.User, &rec.RootKeyID, &rec.Wrapped, &domainKey)
	rec.Domain.PKI = strings.HasPrefix(domainKey, "pki:")
	return rec, err
}

const kekColumns = `id, org_id, domain_org, domain_workspace, domain_project, domain_user, root_key_id, wrapped, domain_key`

func (s *store) ActiveFor(ctx context.Context, org, domainKey string) (sealer.KEKRecord, error) {
	row := s.db.QueryRow(ctx, `SELECT `+kekColumns+`
		FROM keep_kek WHERE org_id = $1 AND domain_key = $2 AND state = 'active'`, org, domainKey)
	rec, err := scanKEK(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return sealer.KEKRecord{}, sealer.ErrNoActiveKEK
	}
	return rec, err
}

func (s *store) Create(ctx context.Context, domainKey string, want sealer.KEKRecord) (sealer.KEKRecord, error) {
	row := s.db.QueryRow(ctx, `
		INSERT INTO keep_kek (id, org_id, domain_key, domain_org, domain_workspace, domain_project, domain_user, root_key_id, wrapped, state)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active')
		ON CONFLICT (org_id, domain_key) WHERE state = 'active' DO NOTHING
		RETURNING `+kekColumns,
		want.ID, want.Org, domainKey, want.Domain.Org, want.Domain.Workspace, want.Domain.Project, want.Domain.User, want.RootKeyID, want.Wrapped)
	rec, err := scanKEK(row)
	if err == nil {
		return rec, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return sealer.KEKRecord{}, err
	}
	// ON CONFLICT DO NOTHING fired: another caller created the active KEK
	// for this domain first.
	rec, err = s.ActiveFor(ctx, want.Org, domainKey)
	if errors.Is(err, sealer.ErrNoActiveKEK) {
		return sealer.KEKRecord{}, fmt.Errorf("builtin: kek insert conflicted but no active kek was found for %s/%s", want.Org, domainKey)
	}
	return rec, err
}

func (s *store) Get(ctx context.Context, org, id string) (sealer.KEKRecord, error) {
	row := s.db.QueryRow(ctx, `SELECT `+kekColumns+` FROM keep_kek WHERE org_id = $1 AND id = $2`, org, id)
	rec, err := scanKEK(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return sealer.KEKRecord{}, sealer.ErrKEKNotFound
	}
	return rec, err
}

func (s *store) queryKEKs(ctx context.Context, org, state string) ([]sealer.KEKRecord, error) {
	rows, err := s.db.Query(ctx, `SELECT `+kekColumns+` FROM keep_kek WHERE org_id = $1 AND state = $2`, org, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sealer.KEKRecord
	for rows.Next() {
		rec, err := scanKEK(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *store) ActiveList(ctx context.Context, org string) ([]sealer.KEKRecord, error) {
	return s.queryKEKs(ctx, org, "active")
}

func (s *store) RetiredList(ctx context.Context, org string) ([]sealer.KEKRecord, error) {
	return s.queryKEKs(ctx, org, "retired")
}

func (s *store) Retire(ctx context.Context, org string, ids []string) error {
	_, err := s.db.Exec(ctx, `UPDATE keep_kek SET state = 'retired' WHERE org_id = $1 AND id = ANY($2) AND state = 'active'`, org, ids)
	return err
}

func (s *store) Purge(ctx context.Context, org string, ids []string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM keep_kek WHERE org_id = $1 AND id = ANY($2) AND state = 'retired'`, org, ids)
	return err
}

// ── sealer.LevelStore ───────────────────────────────────────────────────

func (s *store) Level(ctx context.Context, org string) (sealer.Level, error) {
	var name string
	err := s.db.QueryRow(ctx, `SELECT level FROM keep_org_key_level WHERE org_id = $1`, org).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return sealer.DefaultLevel, nil
	}
	if err != nil {
		return 0, err
	}
	return sealer.ParseLevel(name)
}

// SetLevel persists level as org's current key level. The caller must
// already hold an exclusive Lock for org (see sealer.LevelStore.SetLevel) —
// this alone does not serialise concurrent callers.
func (s *store) SetLevel(ctx context.Context, org string, level sealer.Level, actor string) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO keep_org_key_level (org_id, level, updated_by, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (org_id) DO UPDATE SET level = EXCLUDED.level, updated_by = EXCLUDED.updated_by, updated_at = now()`,
		org, level.String(), actor)
	return err
}

// levelLockKey renders org as the key a Postgres advisory lock hashes — the
// same idiom nextVersion already uses for version allocation.
func levelLockKey(org string) string { return "keep_org_key_level:" + org }

// Lock acquires a session-scoped Postgres advisory lock for org's key level
// on a connection checked out of the pool and held for as long as the
// caller keeps it — not a transaction-scoped lock, because it must span
// several separate statements (ChangeLevel's level read/write, its
// KEKStore calls during Rewrap and retire), which a pgxpool.Pool does not
// guarantee run on the same underlying connection otherwise. exclusive
// selects pg_advisory_lock (blocks every other Lock call for org) or
// pg_advisory_lock_shared (blocks only an exclusive one). See
// sealer.LevelStore.Lock for what each caller must hold it around and how
// the returned Store is meant to be used.
func (s *store) Lock(ctx context.Context, org string, exclusive bool) (sealer.Store, func(context.Context) error, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, nil, err
	}
	key := levelLockKey(org)
	if exclusive {
		_, err = conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, key)
	} else {
		_, err = conn.Exec(ctx, `SELECT pg_advisory_lock_shared(hashtextextended($1, 0))`, key)
	}
	if err != nil {
		conn.Release()
		return nil, nil, err
	}
	// locked runs every Level/SetLevel/KEKStore call through this same
	// connection instead of each borrowing its own from the pool — see
	// LevelStore.Lock's doc comment for why (*pgxpool.Conn satisfies dbtx
	// the same way pgx.Tx does).
	locked := &store{pool: s.pool, db: conn}
	release := func(releaseCtx context.Context) error {
		// A caller's own ctx may already be cancelled (e.g. the request that
		// triggered this call just finished) — the unlock itself must still
		// run, or the lock leaks for the rest of this connection's life.
		releaseCtx = context.WithoutCancel(releaseCtx)
		var uerr error
		if exclusive {
			_, uerr = conn.Exec(releaseCtx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, key)
		} else {
			_, uerr = conn.Exec(releaseCtx, `SELECT pg_advisory_unlock_shared(hashtextextended($1, 0))`, key)
		}
		if uerr != nil {
			// The unlock itself failed — this connection's actual lock
			// state is now unknown (it may still hold it). Closing it here,
			// rather than handing it back to the pool with Release, is what
			// stops a future caller for the same org getting an
			// already-broken connection whose lock they can never actually
			// acquire or release; pgxpool never returns a closed connection
			// to its idle set.
			_ = conn.Conn().Close(releaseCtx)
		}
		conn.Release()
		return uerr
	}
	return locked, release, nil
}

type lockConnKey struct{}

// WithLockConn implements sealer.LockContexter: a Store returned by Lock
// hands ctx back carrying the connection its advisory lock is held on, see
// LockConn.
func (s *store) WithLockConn(ctx context.Context) context.Context {
	if c, ok := s.db.(*pgxpool.Conn); ok {
		return context.WithValue(ctx, lockConnKey{}, c)
	}
	return ctx
}

// TxBeginner is what LockConn returns: the connection the level lock is held on.
type TxBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// LockConn returns the connection the key-level lock is held on, when ctx is
// the context ChangeLevelByName gave its onLocked hook. A hook that writes
// through it (a transaction on that connection) needs no second pool
// connection while it holds the lock; ok is false for any other context.
func LockConn(ctx context.Context) (TxBeginner, bool) {
	c, ok := ctx.Value(lockConnKey{}).(*pgxpool.Conn)
	return c, ok
}

// BindToLock implements sealer.LockBound: ChangeLevel scans and rewraps
// envelopes through the store bound to the connection its level lock is held
// on, instead of borrowing another connection from the pool.
func (s *store) BindToLock(locked sealer.Store) sealer.EnvelopeStore {
	if l, ok := locked.(*store); ok {
		return l
	}
	return s
}

// ── sealer.EnvelopeStore (org-wide: ChangeLevel, Purge) ────────────────────

const envelopeColumns = `store_org, store_workspace, store_project, store_user, secret_id, name, version, kek_id, wrapped_dek, ciphertext`

func scanEnvelope(row rowScanner) (sealer.Ref, sealer.Envelope, error) {
	var ref sealer.Ref
	var env sealer.Envelope
	var version int64
	err := row.Scan(&ref.Store.Org, &ref.Store.Workspace, &ref.Store.Project, &ref.Store.User, &ref.SecretID, &ref.Name, &version, &env.KEKID, &env.WrappedDEK, &env.Ciphertext)
	ref.Version = versionString(version)
	return ref, env, err
}

// Each implements sealer.EnvelopeStore: every envelope of org that still
// names a KEK, in a stable order. Sealer.Purge is Each's only caller, and it
// uses this to compute which KEKs are still referenced. An erased row's
// kek_id is cleared (see erase) precisely so it drops out of this scan —
// crypto-erasure is only as final as the KEK it used eventually becoming
// purgeable, and an erased row that still counted as "using" its old KEK
// would keep that KEK alive forever, exactly the bug
// TestPurge_ReclaimsKEKThatOnlyProtectedErasedVersions (admin_test.go)
// guards against.
func (s *store) Each(ctx context.Context, org string, fn func(sealer.Ref, sealer.Envelope) error) error {
	rows, err := s.db.Query(ctx, `SELECT `+envelopeColumns+`
		FROM keep_envelope WHERE store_org = $1 AND kek_id IS NOT NULL
		ORDER BY store_workspace, store_project, store_user, secret_id, version`, org)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		ref, env, err := scanEnvelope(rows)
		if err != nil {
			return err
		}
		if err := fn(ref, env); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Rewrap implements sealer.EnvelopeStore: reads every envelope of org that
// still has a wrapped DEK first (so the update loop below is not iterating
// a cursor it is also writing through), then calls fn and persists its
// result one row at a time, stopping at the first error — rows already
// replaced stay replaced. Like Each, this filters out erased rows (wrapped_
// dek and kek_id are always cleared together by erase — either column would
// do here): there is no DEK left to re-wrap, and calling fn (which unwraps
// it) on a NULL wrapped_dek would fail every ChangeLevel for the whole
// organisation the moment anything in it was ever erased.
func (s *store) Rewrap(ctx context.Context, org string, fn func(sealer.Ref, sealer.Envelope) (sealer.Envelope, error)) error {
	rows, err := s.db.Query(ctx, `SELECT `+envelopeColumns+`
		FROM keep_envelope WHERE store_org = $1 AND wrapped_dek IS NOT NULL
		ORDER BY store_workspace, store_project, store_user, secret_id, version`, org)
	if err != nil {
		return err
	}
	type item struct {
		ref sealer.Ref
		env sealer.Envelope
	}
	var batch []item
	for rows.Next() {
		ref, env, err := scanEnvelope(rows)
		if err != nil {
			rows.Close()
			return err
		}
		batch = append(batch, item{ref, env})
	}
	rerr := rows.Err()
	rows.Close()
	if rerr != nil {
		return rerr
	}

	for _, it := range batch {
		newEnv, err := fn(it.ref, it.env)
		if err != nil {
			return err
		}
		// "AND status <> 'erased'" closes a window between this loop's own
		// SELECT above and this UPDATE: a concurrent Erase of the same row
		// clears wrapped_dek/kek_id and sets status='erased' to make the
		// version unrecoverable, but this UPDATE's WHERE only named the
		// primary key, so it would blindly overwrite those NULLs with the
		// re-wrap this loop already computed from the row's pre-erase
		// envelope — reviving a value crypto-erasure was supposed to have
		// made permanently unrecoverable. The guard makes the UPDATE a
		// no-op for a row erased in that window instead; fn's work on it is
		// simply discarded, same as if Rewrap's own SELECT had run a moment
		// later and never picked the row up at all.
		if _, err := s.db.Exec(ctx, `UPDATE keep_envelope SET kek_id = $1, wrapped_dek = $2
			WHERE store_org = $3 AND store_workspace = $4 AND store_project = $5 AND store_user = $6 AND secret_id = $7 AND version = $8 AND status <> 'erased'`,
			newEnv.KEKID, newEnv.WrappedDEK, it.ref.Store.Org, it.ref.Store.Workspace, it.ref.Store.Project, it.ref.Store.User, it.ref.SecretID, it.ref.Version); err != nil {
			return err
		}
	}
	return nil
}

// ── per-secret CRUD (Provider, fingerprint key) ─────────────────────────

// envelopeRow is one row of keep_envelope in the shape Provider needs, kept
// separate from sealer.Envelope: it carries version, name and status, which
// the sealer's own Envelope type has no use for.
type envelopeRow struct {
	version int64
	name    string
	kekID   string
	wrapped []byte // wrapped DEK; nil after crypto-erasure
	cipher  []byte
	status  string
}

func scanEnvelopeRow(row rowScanner) (envelopeRow, error) {
	var r envelopeRow
	var kekID *string // NULL exactly for an erased row — see erase
	err := row.Scan(&r.version, &r.name, &kekID, &r.wrapped, &r.cipher, &r.status)
	if kekID != nil {
		r.kekID = *kekID
	}
	return r, err
}

const envelopeRowColumns = `version, name, kek_id, wrapped_dek, ciphertext, status`

// latestActive returns the newest 'active' version of (scope, secretID), or
// errNotFound — the caller (lookup, in provider.go) tells "nothing was ever
// written" apart from "every version is disabled or erased" by following up
// with exists.
func (s *store) latestActive(ctx context.Context, scope sealer.Scope, secretID string) (envelopeRow, error) {
	row := s.db.QueryRow(ctx, `SELECT `+envelopeRowColumns+` FROM keep_envelope
		WHERE store_org = $1 AND store_workspace = $2 AND store_project = $3 AND store_user = $4 AND secret_id = $5 AND status = 'active'
		ORDER BY version DESC LIMIT 1`, scope.Org, scope.Workspace, scope.Project, scope.User, secretID)
	r, err := scanEnvelopeRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return envelopeRow{}, errNotFound
	}
	return r, err
}

// exists reports whether secretID has any version at all in scope,
// regardless of status.
func (s *store) exists(ctx context.Context, scope sealer.Scope, secretID string) (bool, error) {
	var one int
	err := s.db.QueryRow(ctx, `SELECT 1 FROM keep_envelope
		WHERE store_org = $1 AND store_workspace = $2 AND store_project = $3 AND store_user = $4 AND secret_id = $5 LIMIT 1`,
		scope.Org, scope.Workspace, scope.Project, scope.User, secretID).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (s *store) byVersion(ctx context.Context, scope sealer.Scope, secretID string, version int64) (envelopeRow, error) {
	row := s.db.QueryRow(ctx, `SELECT `+envelopeRowColumns+` FROM keep_envelope
		WHERE store_org = $1 AND store_workspace = $2 AND store_project = $3 AND store_user = $4 AND secret_id = $5 AND version = $6`,
		scope.Org, scope.Workspace, scope.Project, scope.User, secretID, version)
	r, err := scanEnvelopeRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return envelopeRow{}, errNotFound
	}
	return r, err
}

// insertIfAbsent inserts a row at a fixed, well-known
// version number (the fingerprint key's version 1): it relies on the
// primary key instead of an advisory lock to let exactly one concurrent
// caller win. inserted is false, with no error, when a row was already
// there.
func (s *store) insertIfAbsent(ctx context.Context, scope sealer.Scope, secretID, name string, version int64, env sealer.Envelope) (inserted bool, err error) {
	tag, err := s.db.Exec(ctx, `INSERT INTO keep_envelope (store_org, store_workspace, store_project, store_user, secret_id, name, version, kek_id, wrapped_dek, ciphertext, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active')
		ON CONFLICT (store_org, store_workspace, store_project, store_user, secret_id, version) DO NOTHING`,
		scope.Org, scope.Workspace, scope.Project, scope.User, secretID, name, version, env.KEKID, env.WrappedDEK, env.Ciphertext)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// lockSecret takes the per-secret transaction-scoped advisory lock inside tx:
// the one lock that serialises version allocation and Disable of the same
// secret. (Erase does not take it: erasing the last active version is an
// administrator's explicit act, so Disable racing Erase is indistinguishable
// from the legal serial order Disable, Erase.) Scoped to tx, so it releases when tx ends however it ends, and
// it needs no connection beyond the one tx already owns.
func lockSecret(ctx context.Context, tx pgx.Tx, scope sealer.Scope, secretID string) error {
	// \x1f (unit separator) keeps fields from colliding across a boundary
	// the way unseparated concatenation could; \x00 is not usable here — a
	// Postgres text value may not contain a NUL byte.
	lockKey := scope.Org + "\x1f" + scope.Workspace + "\x1f" + scope.Project + "\x1f" + scope.User + "\x1f" + secretID
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey)
	return err
}

// nextVersion allocates the next version number of (scope, secretID) inside
// tx, serialised against every other allocation for the same secret by a
// session-local advisory lock — cheap, and scoped to tx so it releases the
// moment tx ends however it ends. There may be no row yet (first version),
// so a lock cannot be taken on the rows themselves.
func nextVersion(ctx context.Context, tx pgx.Tx, scope sealer.Scope, secretID string) (int64, error) {
	if err := lockSecret(ctx, tx, scope, secretID); err != nil {
		return 0, err
	}
	var max *int64
	if err := tx.QueryRow(ctx, `SELECT max(version) FROM keep_envelope
		WHERE store_org = $1 AND store_workspace = $2 AND store_project = $3 AND store_user = $4 AND secret_id = $5`,
		scope.Org, scope.Workspace, scope.Project, scope.User, secretID).Scan(&max); err != nil {
		return 0, err
	}
	if max == nil {
		return 1, nil
	}
	return *max + 1, nil
}

// errLastActive is disableUnlessLast's refusal: the version is the secret's
// only active one.
var errLastActive = errors.New("builtin: last active version")

// disableUnlessLast disables one version unless it is the secret's last
// active one, atomically. The count and the update run in one transaction
// under lockSecret: a single UPDATE with a count subquery is not enough
// under READ COMMITTED, where two concurrent statements each see the other's
// version still active and both disable theirs. A version that is not active
// any more (disabled, erased, or lost to a concurrent call) is a no-op, not
// an error. One pooled connection, no second one.
func (s *store) disableUnlessLast(ctx context.Context, scope sealer.Scope, secretID string, version int64) error {
	tx, err := s.pool.BeginTx(ctx, readCommitted)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()                      // no-op once committed
	if err := lockSecret(ctx, tx, scope, secretID); err != nil { // serialise against parallel Disable
		return err
	}
	var status string
	err = tx.QueryRow(ctx, `SELECT status FROM keep_envelope
		WHERE store_org = $1 AND store_workspace = $2 AND store_project = $3 AND store_user = $4 AND secret_id = $5 AND version = $6`,
		scope.Org, scope.Workspace, scope.Project, scope.User, secretID, version).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return errNotFound
	}
	if err != nil {
		return err
	}
	if status != "active" {
		return nil
	}
	var active int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM keep_envelope
		WHERE store_org = $1 AND store_workspace = $2 AND store_project = $3 AND store_user = $4 AND secret_id = $5 AND status = 'active'`,
		scope.Org, scope.Workspace, scope.Project, scope.User, secretID).Scan(&active); err != nil {
		return err
	}
	if active <= 1 {
		return errLastActive
	}
	if _, err := tx.Exec(ctx, `UPDATE keep_envelope SET status = 'disabled'
		WHERE store_org = $1 AND store_workspace = $2 AND store_project = $3 AND store_user = $4 AND secret_id = $5 AND version = $6 AND status = 'active'`,
		scope.Org, scope.Workspace, scope.Project, scope.User, secretID, version); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// erase performs the crypto-erasure of one version: the wrapped DEK is
// deleted (set to NULL — nothing can unwrap it back) and kek_id is cleared
// too, not only wrapped_dek. Clearing kek_id matters on its own: while it
// still named a KEK, Each (Purge's only source of "still referenced")
// counted this row as using that KEK forever, so the KEK backing an erased
// version could never actually be purged — crypto-erasure was only as
// final as a KEK that stayed alive indefinitely, and a PostgreSQL UPDATE
// leaves the pre-erase row version recoverable as a dead tuple until
// VACUUM, so the KEK eventually being destroyed is what makes this
// irreversible, not merely this row's own wrapped_dek being NULL right
// now. The ciphertext is left in place (still present, permanently
// undecryptable), status becomes 'erased'.
func (s *store) erase(ctx context.Context, scope sealer.Scope, secretID string, version int64) error {
	tag, err := s.db.Exec(ctx, `UPDATE keep_envelope SET wrapped_dek = NULL, kek_id = NULL, status = 'erased'
		WHERE store_org = $1 AND store_workspace = $2 AND store_project = $3 AND store_user = $4 AND secret_id = $5 AND version = $6`,
		scope.Org, scope.Workspace, scope.Project, scope.User, secretID, version)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errNotFound
	}
	return nil
}

// openVersion names one version that erase has not reached yet.
type openVersion struct {
	secretID string
	version  int64
}

// openUnder lists every version in scope whose secret id starts with prefix
// and that still holds a wrapped DEK or a KEK reference: the ones erase has
// work left on. The prefix is compared as a string, not as a LIKE pattern.
func (s *store) openUnder(ctx context.Context, scope sealer.Scope, prefix string) ([]openVersion, error) {
	rows, err := s.db.Query(ctx, `SELECT secret_id, version FROM keep_envelope
		WHERE store_org = $1 AND store_workspace = $2 AND store_project = $3 AND store_user = $4
		  AND left(secret_id, $5) = $6 AND (wrapped_dek IS NOT NULL OR kek_id IS NOT NULL OR status <> 'erased')
		ORDER BY secret_id, version`,
		scope.Org, scope.Workspace, scope.Project, scope.User, len(prefix), prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []openVersion
	for rows.Next() {
		var v openVersion
		if err := rows.Scan(&v.secretID, &v.version); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func versionString(n int64) string { return fmt.Sprintf("%d", n) }
