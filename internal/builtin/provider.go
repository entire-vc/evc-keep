package builtin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// readCommitted is the isolation level of every transaction that takes the
// shared key-level lock. Under REPEATABLE READ the transaction's snapshot is
// taken when its first statement (the lock) starts, before the lock is
// granted, so a Write that waited for a level change would still read the old
// level and seal under the old KEK. The server's default_transaction_isolation
// is a deployment setting; this must not depend on it.
var readCommitted = pgx.TxOptions{IsoLevel: pgx.ReadCommitted}

// unavailable reports a backend failure as provider.ErrUnavailable. A
// database error keeps only its SQLSTATE: pgconn.PgError's Message and Detail
// can quote the offending row ("Failing row contains (...)"), and for
// keep_envelope that row is a wrapped DEK and ciphertext, which must not reach
// a log line or an API error through errors.As or the error text. Any other
// error (a cancelled context, a refused connection) stays wrapped, so callers
// can still test for it.
func unavailable(what string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return fmt.Errorf("%w: %s: sqlstate %s", provider.ErrUnavailable, what, pgErr.Code)
	}
	return fmt.Errorf("%w: %s: %w", provider.ErrUnavailable, what, err)
}

// scrubDB is unavailable's counterpart for errors that are not turned into
// provider.ErrUnavailable: sealer and store errors returned by Admin and by
// the fingerprint key path. A chain that holds a database error is cut down
// to the operation and the SQLSTATE, for the same reason; everything else
// (a refused weakening, a cancelled context) is returned unchanged.
func scrubDB(what string, err error) error {
	var pgErr *pgconn.PgError
	if err != nil && errors.As(err, &pgErr) {
		return fmt.Errorf("builtin: %s: sqlstate %s", what, pgErr.Code)
	}
	return err
}

// gcmNonceAndTag is the fixed size overhead sealer's AES-256-GCM
// construction (crypto/cipher.NewGCM's default: a 12-byte nonce and a
// 16-byte tag) adds around a plaintext value — see internal/builtin/sealer's
// rootkey.go, seal/open. Version uses it to report Meta.Length without
// decrypting; checkVersionMeta (pkg/provider/providertest) cross-checks the
// result against Resolve's real decrypted length, so a wrong constant here
// does not pass silently.
const gcmNonceAndTag = 12 + 16

// Provider implements pkg/provider.Provider for one store (see
// internal/builtin/sealer.Scope) of Keep's built-in secrets, backed by
// PostgreSQL. Construct one per store — its crypto-erasure and fingerprint
// key methods beyond the Provider interface are also store-scoped; the
// org-wide operations (key-level change, KEK purge) are Admin instead.
type Provider struct {
	scope sealer.Scope
	seal  *sealer.Sealer
	db    *store
	log   *slog.Logger

	unavailable atomic.Bool // flipped only from provider_test.go
}

// New returns a Provider over the store scope, sealing and opening through
// seal and persisting to pool. log receives every log line the provider
// emits — providertest.Run reads it back to check nothing in it leaks a
// value (see pkg/provider/providertest).
func New(pool *pgxpool.Pool, seal *sealer.Sealer, scope sealer.Scope, log *slog.Logger) *Provider {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Provider{scope: scope, seal: seal, db: newStore(pool), log: log}
}

func (p *Provider) Capabilities() provider.Capabilities {
	return provider.Capabilities{Versioning: true, Write: true, Disable: true}
}

func (p *Provider) checkAvailable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return unavailable("backend", err)
	}
	if p.unavailable.Load() {
		return fmt.Errorf("%w: builtin backend switched off", provider.ErrUnavailable)
	}
	return nil
}

// lookup resolves ref to its row: ref.Version == "" finds the newest active
// version, distinguishing "nothing was ever written" (ErrNotFound) from
// "versions exist but none is active" (ErrDisabled); a named ref.Version
// returns that row regardless of its status — Resolve rejects a disabled or
// erased one itself, Version does not (mirrors pkg/provider/memory's
// lookup/Resolve split).
func (p *Provider) lookup(ctx context.Context, ref provider.Ref) (envelopeRow, error) {
	if ref.Version == "" {
		row, err := p.db.latestActive(ctx, p.scope, ref.Path)
		if err == nil {
			return row, nil
		}
		if !errors.Is(err, errNotFound) {
			return envelopeRow{}, unavailable("latest active", err)
		}
		exists, eerr := p.db.exists(ctx, p.scope, ref.Path)
		if eerr != nil {
			return envelopeRow{}, unavailable("exists", eerr)
		}
		if exists {
			return envelopeRow{}, fmt.Errorf("%w: %s has no enabled version", provider.ErrDisabled, ref.Path)
		}
		return envelopeRow{}, fmt.Errorf("%w: %s", provider.ErrNotFound, ref.Path)
	}
	n, err := strconv.ParseInt(ref.Version, 10, 64)
	if err != nil || n < 1 {
		return envelopeRow{}, fmt.Errorf("%w: version %q of %s", provider.ErrInvalidRef, ref.Version, ref.Path)
	}
	row, err := p.db.byVersion(ctx, p.scope, ref.Path, n)
	if errors.Is(err, errNotFound) {
		return envelopeRow{}, fmt.Errorf("%w: %s version %d", provider.ErrNotFound, ref.Path, n)
	}
	if err != nil {
		return envelopeRow{}, unavailable("by version", err)
	}
	return row, nil
}

// pathErr classifies ref.Path before it reaches any lookup: empty, or the
// store's own reserved id (fpKeySecretID — see isReservedSecretID). Both are
// ErrInvalidRef, the same class Write/Disable/Erase already use for a
// malformed request. The message names the reserved case ("reserved path");
// the id is a public constant, so that discloses nothing, and a caller sees
// a different class than for an unknown path (ErrNotFound).
func pathErr(path string) error {
	if path == "" {
		return fmt.Errorf("%w: empty path", provider.ErrInvalidRef)
	}
	if isReservedSecretID(path) {
		return fmt.Errorf("%w: reserved path", provider.ErrInvalidRef)
	}
	return nil
}

func (p *Provider) sealerRef(ref provider.Ref, row envelopeRow) sealer.Ref {
	return sealer.Ref{Store: p.scope, SecretID: ref.Path, Name: row.name, Version: versionString(row.version)}
}

func meta(row envelopeRow, length int) provider.Meta {
	return provider.Meta{Version: versionString(row.version), Length: length, Disabled: row.status != "active"}
}

// unwrapLength computes Meta.Length from the stored ciphertext's size
// without decrypting it (see gcmNonceAndTag). It is only ever called with a
// row whose Ciphertext sealer itself produced, so it never goes negative.
func unwrapLength(cipher []byte) int { return len(cipher) - gcmNonceAndTag }

func (p *Provider) Resolve(ctx context.Context, ref provider.Ref) (secret.Value, provider.Meta, error) {
	if err := p.checkAvailable(ctx); err != nil {
		return secret.Value{}, provider.Meta{}, err
	}
	if err := pathErr(ref.Path); err != nil {
		return secret.Value{}, provider.Meta{}, err
	}
	row, err := p.lookup(ctx, ref)
	if err != nil {
		return secret.Value{}, provider.Meta{}, err
	}
	if row.status != "active" {
		return secret.Value{}, provider.Meta{}, fmt.Errorf("%w: %s version %d", provider.ErrDisabled, ref.Path, row.version)
	}
	v, err := p.seal.Open(ctx, p.sealerRef(ref, row), sealer.Envelope{KEKID: row.kekID, WrappedDEK: row.wrapped, Ciphertext: row.cipher})
	if err != nil {
		// Should not happen on a row this package wrote itself; treat it as
		// "cannot serve this right now" rather than inventing a new
		// pkg/provider error class for it.
		p.log.Error("open failed", "secret_id", loggableID(ref.Path), "version_id", versionString(row.version))
		return secret.Value{}, provider.Meta{}, fmt.Errorf("%w: open failed", provider.ErrUnavailable)
	}
	p.log.Debug("resolve", "secret_id", loggableID(ref.Path), "version_id", versionString(row.version))
	return v, meta(row, v.Len()), nil
}

func (p *Provider) Write(ctx context.Context, ref provider.Ref, v secret.Value) (provider.Meta, error) {
	if err := p.checkAvailable(ctx); err != nil {
		return provider.Meta{}, err
	}
	if err := pathErr(ref.Path); err != nil {
		return provider.Meta{}, err
	}
	if ref.Version != "" {
		return provider.Meta{}, fmt.Errorf("%w: write must not name a version", provider.ErrInvalidRef)
	}

	tx, err := p.db.pool.BeginTx(ctx, readCommitted)
	if err != nil {
		return provider.Meta{}, unavailable("begin", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	// The shared side of org's key-level lock, held for the rest of this
	// transaction — i.e. for the whole read-level-then-persist sequence
	// below, not only around Seal (see ChangeLevel's doc comment for the
	// race this closes). It is taken as pg_advisory_xact_lock_shared inside
	// this tx, not through a separately pool-acquired connection: an
	// earlier version held the lock on its own connection while this tx and
	// Seal's own Level/KEK lookups each borrowed one more from the pool, up
	// to three at once for one Write — enough concurrent writers to exhaust
	// a modestly-sized pool and hang everyone on it, including
	// Sealer.ChangeLevel's own follow-up queries once it holds the
	// exclusive side of this same lock (reproduced live under a small
	// connection pool). Binding the lock and every store call below to this
	// one tx keeps the whole operation to the one connection the
	// transaction already owns.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))`, levelLockKey(p.scope.Org)); err != nil {
		return provider.Meta{}, unavailable("lock", err)
	}

	version, err := nextVersion(ctx, tx, p.scope, ref.Path)
	if err != nil {
		return provider.Meta{}, unavailable("allocate version", err)
	}

	sref := sealer.Ref{Store: p.scope, SecretID: ref.Path, Name: ref.Path, Version: versionString(version)}
	env, err := p.seal.WithStore(p.db.withTx(tx)).Seal(ctx, sref, v)
	if err != nil {
		return provider.Meta{}, fmt.Errorf("%w: seal failed", provider.ErrUnavailable)
	}

	if _, err := tx.Exec(ctx, `INSERT INTO keep_envelope (store_org, store_workspace, store_project, store_user, secret_id, name, version, kek_id, wrapped_dek, ciphertext, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active')`,
		p.scope.Org, p.scope.Workspace, p.scope.Project, p.scope.User, ref.Path, ref.Path, version, env.KEKID, env.WrappedDEK, env.Ciphertext); err != nil {
		return provider.Meta{}, unavailable("insert", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return provider.Meta{}, unavailable("commit", err)
	}

	p.log.Info("write", "secret_id", loggableID(ref.Path), "version_id", versionString(version))
	return provider.Meta{Version: sref.Version, Length: v.Len()}, nil
}

func (p *Provider) Version(ctx context.Context, ref provider.Ref) (provider.Meta, error) {
	if err := p.checkAvailable(ctx); err != nil {
		return provider.Meta{}, err
	}
	if err := pathErr(ref.Path); err != nil {
		return provider.Meta{}, err
	}
	row, err := p.lookup(ctx, ref)
	if err != nil {
		return provider.Meta{}, err
	}
	return meta(row, unwrapLength(row.cipher)), nil
}

func (p *Provider) Disable(ctx context.Context, ref provider.Ref) error {
	if err := p.checkAvailable(ctx); err != nil {
		return err
	}
	if err := pathErr(ref.Path); err != nil {
		return err
	}
	if ref.Version == "" {
		return fmt.Errorf("%w: disable must name a version", provider.ErrInvalidRef)
	}
	n, err := strconv.ParseInt(ref.Version, 10, 64)
	if err != nil || n < 1 {
		return fmt.Errorf("%w: version %q of %s", provider.ErrInvalidRef, ref.Version, ref.Path)
	}
	switch err := p.db.disableUnlessLast(ctx, p.scope, ref.Path, n); {
	case errors.Is(err, errNotFound):
		return fmt.Errorf("%w: %s version %d", provider.ErrNotFound, ref.Path, n)
	case errors.Is(err, errLastActive):
		return fmt.Errorf("%w: %s version %d", provider.ErrLastVersion, ref.Path, n)
	case err != nil:
		return unavailable("disable", err)
	}
	p.log.Info("disable", "secret_id", loggableID(ref.Path), "version_id", versionString(n))
	return nil
}

// Erase performs crypto-erasure of one version: its wrapped DEK and KEK
// reference are deleted, its ciphertext stays. That makes the version
// unreadable through this provider, and unrecoverable once nothing else can
// unwrap the old DEK: the KEK it was wrapped under is retired and purged
// (Admin.Purge, after a level change moves other envelopes off it) and the
// dead row versions are vacuumed away. At the "user" key level the KEK is
// still live and still protects the user's other secrets, so it is not
// purged; a copy of the wrapped DEK taken from dead tuples, WAL or a backup
// then stays unwrappable for as long as that KEK exists. Retention of WAL and
// backups is a deployment policy, not something this method controls. It is
// not part of pkg/provider.Provider — an administrative operation with no
// generic-provider equivalent, invoked directly by the caller that already
// checked the actor is authorized (this package has no notion of roles).
func (p *Provider) Erase(ctx context.Context, ref provider.Ref) error {
	if err := p.checkAvailable(ctx); err != nil {
		return err
	}
	if err := pathErr(ref.Path); err != nil {
		return err
	}
	if ref.Version == "" {
		return fmt.Errorf("%w: erase must name a version", provider.ErrInvalidRef)
	}
	n, err := strconv.ParseInt(ref.Version, 10, 64)
	if err != nil || n < 1 {
		return fmt.Errorf("%w: version %q of %s", provider.ErrInvalidRef, ref.Version, ref.Path)
	}
	if err := p.db.erase(ctx, p.scope, ref.Path, n); err != nil {
		if errors.Is(err, errNotFound) {
			return fmt.Errorf("%w: %s version %d", provider.ErrNotFound, ref.Path, n)
		}
		return unavailable("erase", err)
	}
	p.log.Info("erase", "secret_id", loggableID(ref.Path), "version_id", versionString(n))
	return nil
}

// loggableID is deliberately a no-op today (secret ids are catalog-chosen
// opaque identifiers, not values — see pkg/provider.Ref's doc comment) —
// named so it is visible at a glance that every log call above passed its
// id through here, not the value.
func loggableID(id string) string { return id }
