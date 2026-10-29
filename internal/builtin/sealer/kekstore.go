package sealer

import (
	"context"
	"errors"
)

// KEKRecord is one KEK as the store persists it. Wrapped is opaque outside
// the sealer: it authenticates only under the root key named by RootKeyID,
// with an AAD built from ID, Org and Domain (see kekAAD). Nothing in it is
// plaintext key material — only the store's caller (this package) ever
// unwraps it, and only for the duration of one operation.
type KEKRecord struct {
	ID        string
	Org       string
	Domain    Scope
	RootKeyID string
	Wrapped   []byte
}

// ErrNoActiveKEK is returned by KEKStore.ActiveFor when domainKey has no
// active KEK yet — not an error condition for the sealer, which creates one
// on this signal.
var ErrNoActiveKEK = errors.New("sealer: no active kek for domain")

// ErrKEKNotFound is returned by KEKStore.Get when id does not exist within
// org — distinct from any other error Get can return (a transient backend
// failure), so a caller like Sealer.unwrapDEK can tell "this envelope's key
// is genuinely gone" from "the backend could not answer right now" and not
// mask the second as the first.
var ErrKEKNotFound = errors.New("sealer: kek not found")

// KEKStore persists the KEK records of one Sealer's key hierarchy, scoped to
// organisations. domainKey is the stable identifier a Scope renders via its
// key method — the store treats it as an opaque string, not a Scope it has
// to parse.
//
// Every method is scoped to the org passed in; a store implementation must
// never let an id or domainKey from one org resolve a KEK of another (see
// TestGet_DoesNotCrossOrgBoundary and the C6 checks that depend on it).
type KEKStore interface {
	// ActiveFor returns the KEK currently active for domainKey within org,
	// or ErrNoActiveKEK if none exists yet.
	ActiveFor(ctx context.Context, org, domainKey string) (KEKRecord, error)

	// Create makes want the active KEK for domainKey, atomically: if another
	// caller raced it and already created the active KEK for that domain,
	// Create returns that existing record instead of want, and want is
	// simply not used. It never returns two different "active" records for
	// the same (org, domainKey).
	Create(ctx context.Context, domainKey string, want KEKRecord) (KEKRecord, error)

	// Get returns the KEK record named id within org, active or retired. It
	// returns an error if id does not exist or belongs to a different org.
	Get(ctx context.Context, org, id string) (KEKRecord, error)

	// ActiveList returns every KEK currently active for org.
	ActiveList(ctx context.Context, org string) ([]KEKRecord, error)

	// RetiredList returns every KEK of org that is retired but not yet
	// purged.
	RetiredList(ctx context.Context, org string) ([]KEKRecord, error)

	// Retire marks the named KEKs of org retired: no longer any domain's
	// active KEK, but still readable through Get until Purge deletes them.
	// Retiring an already-retired id is a no-op, not an error.
	Retire(ctx context.Context, org string, ids []string) error

	// Purge deletes the named KEKs of org — crypto-erasure of whatever they
	// still wrap. The caller has already checked that no envelope refers to
	// any of them any more.
	Purge(ctx context.Context, org string, ids []string) error
}

// Store is the full persistence a Sealer needs: KEKStore for its KEK
// records and LevelStore for its organisations' key levels. A single
// PostgreSQL-backed type may implement both, as internal/builtin's does.
type Store interface {
	KEKStore
	LevelStore
}
