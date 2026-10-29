package catalog

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/entire-vc/evc-keep/internal/metatext"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CreateRefInput describes a new catalog entry — metadata only. Writing the
// value itself is a provider's job (W2); this never touches one.
type CreateRefInput struct {
	Org         uuid.UUID
	Scope       tenancy.Scope
	Name        string
	Class       string
	Type        string
	ProviderRef string
	Description string // "" stored as SQL NULL
	// StoreID overrides ResolveStore's own StoreBinding walk when set.
	// Zero (uuid.Nil) means "resolve it".
	StoreID uuid.UUID
}

// CreateRef creates a new secret reference at in.Scope: resolves its store
// via StoreBinding (walking up through in.Scope's ancestors, tenancy model
// §3) unless in.StoreID is given, and refuses if any ancestor OverrideLock
// blocks this name, this class, or (once a store is chosen) this store for
// this class.
//
// Every check and the INSERT it gates run inside one transaction. Before
// reading locks at any ancestor, it takes [lockScope] on that ancestor —
// the same lock [Catalog.CreateOverrideLock] takes on its own target scope
// before inserting — so a lock created at an ancestor scope and a CreateRef
// racing against it can only ever resolve as one of the two sequential
// orderings, never as "CreateRef read the lock set before the lock existed,
// then inserted after it did". See lockScope's own doc and
// concurrency_test.go (TestCreateRef_OverrideLockRace), which exercises
// exactly this pair on a real database with N≥50 forced-overlap iterations.
//
// This is a narrower tool than either locking every read row FOR SHARE (an
// OverrideLock that does not exist yet has no row to lock) or running the
// whole transaction at SERIALIZABLE (CreateOverrideLock never reads
// anything CreateRef writes, so the two have no cycle for Postgres's
// predicate-lock conflict detection to catch — SSI would not abort either
// side here). An explicit advisory lock keyed by (org, scope) is the
// mechanism that actually serializes this specific pair; requireUsableStore
// still reads the chosen store's row FOR SHARE, for the separate store
// TOCTOU finding it closes (see its own doc).
func (c *Catalog) CreateRef(ctx context.Context, in CreateRefInput) (tenancy.SecretRef, error) {
	for _, field := range []struct {
		name, value string
		limit       int
	}{
		{"name", in.Name, metatext.NameLimit},
		{"description", in.Description, metatext.DescriptionLimit},
		{"class", in.Class, metatext.LabelLimit},
		{"type", in.Type, metatext.LabelLimit},
	} {
		if err := metatext.Validate(field.name, field.value, field.limit); err != nil {
			return tenancy.SecretRef{}, err
		}
	}
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return tenancy.SecretRef{}, fmt.Errorf("catalog: begin create ref: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed below

	chain, err := ancestorChainTx(ctx, tx, in.Org, in.Scope)
	if err != nil {
		return tenancy.SecretRef{}, err
	}
	ancestors := chain[1:] // everything strictly above in.Scope — locks at in.Scope itself never block it

	// Take every ancestor's scope lock up front, before reading anything at
	// any of them: whichever of this transaction and a concurrent
	// CreateOverrideLock targeting one of these scopes gets here first,
	// the other waits for it to fully commit or roll back. The lock sets
	// read below therefore cannot change out from under this transaction,
	// so they are read once and cached rather than re-queried after store
	// resolution.
	for _, anc := range ancestors {
		if err := lockScope(ctx, tx, in.Org, anc); err != nil {
			return tenancy.SecretRef{}, err
		}
	}

	if in.StoreID != uuid.Nil {
		if err := requireUsableStore(ctx, tx, in.Org, chain, in.StoreID); err != nil {
			return tenancy.SecretRef{}, err
		}
	}

	ancestorLocks := make(map[tenancy.Scope][]OverrideLock, len(ancestors))
	for _, anc := range ancestors {
		locks, err := locksAt(ctx, tx, in.Org, anc)
		if err != nil {
			return tenancy.SecretRef{}, err
		}
		ancestorLocks[anc] = locks
		for _, lk := range locks {
			switch {
			case lk.Mode == ModeName && lk.SelectorName != nil && *lk.SelectorName == in.Name:
				return tenancy.SecretRef{}, overrideLockedError("name", in.Name, anc.Level)
			case lk.Mode == ModeClass && lk.SelectorClass != nil && *lk.SelectorClass == in.Class:
				return tenancy.SecretRef{}, overrideLockedError("class", in.Class, anc.Level)
			}
		}
	}

	storeID := in.StoreID
	if storeID == uuid.Nil {
		storeID, err = resolveStoreTx(ctx, tx, in.Org, chain)
		if err != nil {
			return tenancy.SecretRef{}, err
		}
		// A binding was checked when it was made, but the store's status
		// can change afterwards: re-check what the walk found, so a store
		// disabled since is not silently used.
		if err := requireUsableStore(ctx, tx, in.Org, chain, storeID); err != nil {
			return tenancy.SecretRef{}, err
		}
	}

	for _, anc := range ancestors {
		for _, lk := range ancestorLocks[anc] {
			if lk.Mode == ModeStore && lk.SelectorClass != nil && *lk.SelectorClass == in.Class && !containsStore(lk.AllowedStoreIDs, storeID) {
				return tenancy.SecretRef{}, overrideLockedError("class", in.Class, anc.Level)
			}
		}
	}

	id, err := uuid.NewV7()
	if err != nil {
		return tenancy.SecretRef{}, fmt.Errorf("catalog: generate secret id: %w", err)
	}
	var descPtr *string
	if in.Description != "" {
		descPtr = &in.Description
	}

	beforeInsertHook(ctx)

	var s tenancy.SecretRef
	s.Scope = in.Scope
	err = tx.QueryRow(ctx,
		`INSERT INTO secrets (id, org_id, scope_level, scope_id, name, class, type, store_id, provider_ref, description)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING id, org_id, name, class, type, store_id, provider_ref, description, status, created_at, updated_at`,
		id, in.Org, string(in.Scope.Level), in.Scope.ID, in.Name, in.Class, in.Type, storeID, in.ProviderRef, descPtr,
	).Scan(&s.ID, &s.OrgID, &s.Name, &s.Class, &s.Type, &s.StoreID, &s.ProviderRef, &s.Description, &s.Status, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		if uniqueViolation(err) {
			return tenancy.SecretRef{}, duplicateNameError()
		}
		return tenancy.SecretRef{}, fmt.Errorf("catalog: create ref: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return tenancy.SecretRef{}, fmt.Errorf("catalog: commit create ref: %w", err)
	}
	return s, nil
}

// List returns every secret defined exactly at scope (no hierarchy walk —
// that is internal/tenancy.Resolve's job), ordered by name.
func (c *Catalog) List(ctx context.Context, org uuid.UUID, scope tenancy.Scope) ([]tenancy.SecretRef, error) {
	rows, err := c.pool.Query(ctx,
		`SELECT id, org_id, name, class, type, store_id, provider_ref, description, status, created_at, updated_at
		 FROM secrets WHERE org_id = $1 AND scope_level = $2 AND scope_id = $3 ORDER BY name`,
		org, string(scope.Level), scope.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("catalog: list secrets: %w", err)
	}
	defer rows.Close()
	var out []tenancy.SecretRef
	for rows.Next() {
		s := tenancy.SecretRef{Scope: scope}
		if err := rows.Scan(&s.ID, &s.OrgID, &s.Name, &s.Class, &s.Type, &s.StoreID, &s.ProviderRef, &s.Description, &s.Status, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("catalog: scan secret: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: list secrets: %w", err)
	}
	return out, nil
}

// Meta looks up a secret by id, scoped to org, and returns the same
// not-found error whether no such id exists at all or it names a secret
// whose scope is not in reachable — reachable is the caller's own chain
// (tenancy model §7 scenario C2: lookup by id, not just by name, must fail
// the same way — a scope outside the caller's chain must never be
// distinguishable from a scope that does not exist).
func (c *Catalog) Meta(ctx context.Context, org, id uuid.UUID, reachable []tenancy.Scope) (tenancy.SecretRef, error) {
	var s tenancy.SecretRef
	err := c.pool.QueryRow(ctx,
		`SELECT id, org_id, scope_level, scope_id, name, class, type, store_id, provider_ref, description, status, created_at, updated_at
		 FROM secrets WHERE org_id = $1 AND id = $2`,
		org, id,
	).Scan(&s.ID, &s.OrgID, &s.Scope.Level, &s.Scope.ID, &s.Name, &s.Class, &s.Type, &s.StoreID, &s.ProviderRef, &s.Description, &s.Status, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return tenancy.SecretRef{}, notFoundByID(id)
		}
		return tenancy.SecretRef{}, fmt.Errorf("catalog: get secret meta: %w", err)
	}
	if !scopeReachable(s.Scope, reachable) {
		return tenancy.SecretRef{}, notFoundByID(id)
	}
	return s, nil
}

func scopeReachable(s tenancy.Scope, reachable []tenancy.Scope) bool {
	for _, r := range reachable {
		if r.Level == s.Level && r.ID == s.ID {
			return true
		}
	}
	return false
}

// SecretVersion is a secret_versions row: one per pkg/provider.Meta a
// provider has ever returned for a Write on this secret. fingerprint is a
// keyed HMAC (pkg/fingerprint) — never a plain hash, never the value.
type SecretVersion struct {
	ID              uuid.UUID
	OrgID           uuid.UUID
	SecretID        uuid.UUID
	ProviderVersion string
	Fingerprint     string
	Length          int
	Disabled        bool
	CreatedAt       time.Time
}

// AddVersion records a new version of secretID. It never receives a value —
// only what a provider.Write already reported as [provider.Meta] plus the
// fingerprint pkg/fingerprint computed from the value it was given, neither
// of which is reversible back to the value.
func (c *Catalog) AddVersion(ctx context.Context, org, secretID uuid.UUID, providerVersion, fingerprint string, length int) (SecretVersion, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return SecretVersion{}, fmt.Errorf("catalog: generate version id: %w", err)
	}
	var v SecretVersion
	err = c.pool.QueryRow(ctx,
		`INSERT INTO secret_versions (id, org_id, secret_id, provider_version, fingerprint, length)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, org_id, secret_id, provider_version, fingerprint, length, disabled, created_at`,
		id, org, secretID, providerVersion, fingerprint, length,
	).Scan(&v.ID, &v.OrgID, &v.SecretID, &v.ProviderVersion, &v.Fingerprint, &v.Length, &v.Disabled, &v.CreatedAt)
	if err != nil {
		return SecretVersion{}, fmt.Errorf("catalog: add version: %w", err)
	}
	return v, nil
}

// ListVersions returns every version of secretID, newest first.
func (c *Catalog) ListVersions(ctx context.Context, org, secretID uuid.UUID) ([]SecretVersion, error) {
	rows, err := c.pool.Query(ctx,
		`SELECT id, org_id, secret_id, provider_version, fingerprint, length, disabled, created_at
		 FROM secret_versions WHERE org_id = $1 AND secret_id = $2 ORDER BY created_at DESC`,
		org, secretID,
	)
	if err != nil {
		return nil, fmt.Errorf("catalog: list versions: %w", err)
	}
	defer rows.Close()
	var out []SecretVersion
	for rows.Next() {
		var v SecretVersion
		if err := rows.Scan(&v.ID, &v.OrgID, &v.SecretID, &v.ProviderVersion, &v.Fingerprint, &v.Length, &v.Disabled, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("catalog: scan version: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: list versions: %w", err)
	}
	return out, nil
}
