package builtin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/entire-vc/evc-keep/internal/builtin/sealer"
	"github.com/entire-vc/evc-keep/pkg/fingerprint"
	"github.com/entire-vc/evc-keep/pkg/provider"
	"github.com/entire-vc/evc-keep/pkg/secret"
)

// fpKeySecretID is the reserved secret id a store's fingerprint key is
// sealed under — the same envelope table and sealer.Seal/Open path as any
// other secret, at a fixed version (1: the key is never rotated by writing
// a new version of it). No real secret can collide with it: secret ids are
// provider.Ref.Path values chosen by the catalog, and this one is reserved.
const fpKeySecretID = "__keep_fingerprint_key__" // #nosec G101 -- an id, not a credential

// isReservedSecretID reports whether path names storage the Provider
// interface must never resolve, write, version, disable or erase as an
// ordinary secret — today, only the store's own fingerprint key. Every
// Provider method checks this before touching the row; FingerprintKey and
// openFingerprintKey read and write that row directly through p.db, not
// through those guarded methods, so the guard never blocks them.
func isReservedSecretID(path string) bool { return path == fpKeySecretID || path == intakeKeySecretID }

// FingerprintKey returns the store's fingerprint key (threat model §4.1),
// generating and sealing a fresh one on first use under this store's KEK —
// exactly like any other secret's DEK, per the tenancy model: a KEK
// compromise of one store must not help fingerprint another's values. Later
// calls, including after a restart, unseal and return the same key — see
// pkg/fingerprint's doc comment on why the key must be stable per store.
func (p *Provider) FingerprintKey(ctx context.Context) (fingerprint.Key, error) {
	if err := p.checkAvailable(ctx); err != nil {
		return fingerprint.Key{}, err
	}
	row, err := p.db.byVersion(ctx, p.scope, fpKeySecretID, 1)
	if err == nil {
		return p.openFingerprintKey(ctx, row)
	}
	if !errors.Is(err, errNotFound) {
		return fingerprint.Key{}, unavailable("by version", err)
	}

	id, err := randomFPKeyID()
	if err != nil {
		return fingerprint.Key{}, err
	}
	k, err := fingerprint.GenerateKey(id)
	if err != nil {
		return fingerprint.Key{}, err
	}

	tx, err := p.db.pool.BeginTx(ctx, readCommitted)
	if err != nil {
		k.Wipe()
		return fingerprint.Key{}, unavailable("begin", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed

	// Same lock, same reason, and same one-connection shape as
	// Provider.Write's own first write — see its doc comment.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))`, levelLockKey(p.scope.Org)); err != nil {
		k.Wipe()
		return fingerprint.Key{}, unavailable("lock", err)
	}

	txStore := p.db.withTx(tx)
	sref := sealer.Ref{Store: p.scope, SecretID: fpKeySecretID, Name: id, Version: "1"}
	var env sealer.Envelope
	var sealErr error
	fingerprint.ExposeKey(k, func(b []byte) {
		v := secret.New(b)
		env, sealErr = p.seal.WithStore(txStore).Seal(ctx, sref, v)
		v.Wipe()
	})
	if sealErr != nil {
		k.Wipe()
		// Same class, same reason as Write's identical wrapping: sealErr
		// can carry a raw pgx/transaction error (e.g. from the lock
		// statement above, run inside the same tx Seal's own store calls
		// use), and provider.ErrUnavailable is the right class for "seal
		// failed for a backend reason", not a bespoke unwrapped error.
		return fingerprint.Key{}, fmt.Errorf("%w: seal failed", provider.ErrUnavailable)
	}

	inserted, err := txStore.insertIfAbsent(ctx, p.scope, fpKeySecretID, id, 1, env)
	if err != nil {
		k.Wipe()
		return fingerprint.Key{}, unavailable("insert", err)
	}
	if !inserted {
		k.Wipe()
		// A concurrent caller created version 1 first; roll this attempt
		// back and unseal theirs instead of ours below, outside the tx.
		_ = tx.Rollback(ctx)
	} else if err := tx.Commit(ctx); err != nil {
		k.Wipe()
		return fingerprint.Key{}, unavailable("commit", err)
	}
	if inserted {
		return k, nil
	}
	// Unseal the winner's row instead of ours, so every reader of this
	// store agrees on one fingerprint key.
	row, err = p.db.byVersion(ctx, p.scope, fpKeySecretID, 1)
	if err != nil {
		return fingerprint.Key{}, unavailable("by version", err)
	}
	return p.openFingerprintKey(ctx, row)
}

func (p *Provider) openFingerprintKey(ctx context.Context, row envelopeRow) (fingerprint.Key, error) {
	sref := sealer.Ref{Store: p.scope, SecretID: fpKeySecretID, Name: row.name, Version: versionString(row.version)}
	v, err := p.seal.Open(ctx, sref, sealer.Envelope{KEKID: row.kekID, WrappedDEK: row.wrapped, Ciphertext: row.cipher})
	if err != nil {
		return fingerprint.Key{}, scrubDB("open fingerprint key", fmt.Errorf("builtin: open fingerprint key: %w", err))
	}
	var k fingerprint.Key
	var kerr error
	secret.Expose(v, func(b []byte) { k, kerr = fingerprint.NewKey(row.name, b) })
	v.Wipe()
	return k, kerr
}

// randomFPKeyID returns a fresh id satisfying fingerprint.Key's [a-z0-9]{1,16}
// format — a fixed-per-store id derived from the scope would be simpler, but
// scope fields can contain characters that regex forbids, so a random id
// stored alongside the sealed key (in the envelope's name column) is what
// makes the key recoverable after a restart regardless of the scope's shape.
func randomFPKeyID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("builtin: generate fingerprint key id: %w", err)
	}
	return hex.EncodeToString(b), nil // 12 lowercase hex chars, well within [a-z0-9]{1,16}
}
