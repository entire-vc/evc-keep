package catalog

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/metatext"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Catalog is the store/binding/lock/secret repository. Every method takes
// org explicitly and filters on it — see the package doc and
// internal/tenancy's doc on why.
type Catalog struct {
	pool *pgxpool.Pool
}

// New returns a Catalog backed by pool.
func New(pool *pgxpool.Pool) *Catalog { return &Catalog{pool: pool} }

// Store is a stores row: a connected provider instance.
type Store struct {
	ID         uuid.UUID
	OrgID      uuid.UUID
	Provider   string
	Name       string
	OwnerScope tenancy.Scope
	Status     string
	CreatedAt  time.Time
}

// CreateStore inserts a new active store. ownerScope must name an existing
// scope of org — like [tenancy.Repo.CreateService], the INSERT is gated by
// the schema's own keep_validate_scope (the same function backing the
// stores table's CHECK) so a scope that does not belong to org is refused
// as [apperr.ClassInvalidArgument] before any row is written, instead of
// surfacing as an unclassified CHECK-constraint failure.
func (c *Catalog) CreateStore(ctx context.Context, org uuid.UUID, provider, name string, ownerScope tenancy.Scope) (Store, error) {
	if err := metatext.Validate("name", name, metatext.NameLimit); err != nil {
		return Store{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Store{}, fmt.Errorf("catalog: generate store id: %w", err)
	}
	return insertStoreTx(ctx, c.pool, id, org, provider, name, ownerScope)
}

// insertStoreTx is CreateStore's INSERT, run through db: the pool for
// CreateStore, the open transaction for EnsureDefaultBuiltinStore.
func insertStoreTx(ctx context.Context, db dbtx, id, org uuid.UUID, provider, name string, ownerScope tenancy.Scope) (Store, error) {
	var s Store
	err := db.QueryRow(ctx,
		`INSERT INTO stores (id, org_id, provider, name, owner_scope_level, owner_scope_id)
		 SELECT $1, $2, $3, $4, $5, $6 WHERE keep_validate_scope($2, $5, $6)
		 RETURNING id, org_id, provider, name, owner_scope_level, owner_scope_id, status, created_at`,
		id, org, provider, name, string(ownerScope.Level), ownerScope.ID,
	).Scan(&s.ID, &s.OrgID, &s.Provider, &s.Name, &s.OwnerScope.Level, &s.OwnerScope.ID, &s.Status, &s.CreatedAt)
	if err != nil {
		if uniqueViolation(err) {
			return Store{}, apperr.New(apperr.ClassAlreadyExists, "a builtin store already exists at this scope")
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return Store{}, invalidScope("owner scope does not belong to this organization")
		}
		return Store{}, fmt.Errorf("catalog: create store: %w", err)
	}
	return s, nil
}

// StoreBinding is a store_bindings row: "at this scope, the default store
// is this one" (tenancy model §1, §3).
type StoreBinding struct {
	ID        uuid.UUID
	OrgID     uuid.UUID
	Scope     tenancy.Scope
	StoreID   uuid.UUID
	CreatedAt time.Time
}

// CreateStoreBinding sets scope's default store. One binding per scope —
// the schema's UNIQUE (org_id, scope_level, scope_id) is what enforces
// that; a race on it (two callers binding the same scope at once) surfaces
// as [apperr.ClassAlreadyExists], never a raw database error.
//
// The store must be usable for the scope, by the same rule as an explicit
// choice in CreateRef ([requireUsableStore]): active and owned by the scope
// or one of its ancestors. A binding is the implicit way of choosing a
// store for every later CreateRef, so it must not be a way around that
// rule — and that check and the INSERT it gates run inside one transaction,
// the store's row held FOR SHARE throughout, so a concurrent status change
// (there is no such mutator yet, but see requireUsableStore's own doc)
// cannot land between "checked usable" and "bound" the way it could when
// the two were separate, unsynchronized round trips. See concurrency_test.go
// (TestCreateStoreBinding_DisableRace).
func (c *Catalog) CreateStoreBinding(ctx context.Context, org uuid.UUID, scope tenancy.Scope, storeID uuid.UUID) (StoreBinding, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return StoreBinding{}, fmt.Errorf("catalog: generate store binding id: %w", err)
	}

	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return StoreBinding{}, fmt.Errorf("catalog: begin create store binding: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed below

	chain, err := ancestorChainTx(ctx, tx, org, scope)
	if err != nil {
		return StoreBinding{}, err
	}
	if err := requireUsableStore(ctx, tx, org, chain, storeID); err != nil {
		return StoreBinding{}, err
	}

	beforeInsertHook(ctx)

	var b StoreBinding
	err = tx.QueryRow(ctx,
		`INSERT INTO store_bindings (id, org_id, scope_level, scope_id, store_id)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, org_id, scope_level, scope_id, store_id, created_at`,
		id, org, string(scope.Level), scope.ID, storeID,
	).Scan(&b.ID, &b.OrgID, &b.Scope.Level, &b.Scope.ID, &b.StoreID, &b.CreatedAt)
	if err != nil {
		if uniqueViolation(err) {
			return StoreBinding{}, alreadyBoundError()
		}
		return StoreBinding{}, fmt.Errorf("catalog: create store binding: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return StoreBinding{}, fmt.Errorf("catalog: commit create store binding: %w", err)
	}
	return b, nil
}

// DefaultBuiltinStoreName is the name of the builtin store
// [Catalog.EnsureDefaultBuiltinStore] creates at the organization scope.
const DefaultBuiltinStoreName = "default"

// EnsureDefaultBuiltinStore makes sure org's own scope has a bound store, so
// that CreateRef into the organization (or any scope under it that binds
// nothing of its own) has a store to resolve to. keep-server bootstrap-org
// calls it for a new organization, keep-server bind-default-store for one
// created before.
//
// If the org scope is already bound, nothing changes and the bound store is
// returned, whichever it is. Otherwise the builtin store "default" owned by
// the org scope is bound, created first if it does not exist yet. created
// reports whether a binding was written. The store, if new, and the binding
// are written in one transaction: no store is left behind without its
// binding. The organization's row is held FOR NO KEY UPDATE throughout, so
// two concurrent calls for the same org run one after the other and the
// second finds the first one's binding. The binding goes through the same
// rule as CreateStoreBinding ([requireUsableStore]): a disabled "default"
// store is refused, not bound.
//
// An unknown org is [apperr.ClassNotFound]. A builtin store of another name
// at the org scope (one builtin store per owner scope) is
// [apperr.ClassAlreadyExists]: bind it explicitly instead.
func (c *Catalog) EnsureDefaultBuiltinStore(ctx context.Context, org uuid.UUID) (storeID uuid.UUID, created bool, err error) {
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("catalog: begin ensure default store: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op once committed below

	var one int
	err = tx.QueryRow(ctx, `SELECT 1 FROM organizations WHERE id = $1 FOR NO KEY UPDATE`, org).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, false, apperr.New(apperr.ClassNotFound, "organization not found")
	}
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("catalog: lock organization: %w", err)
	}
	scope := tenancy.Org(org)
	bound, ok, err := storeBindingAt(ctx, tx, org, scope)
	if err != nil {
		return uuid.Nil, false, err
	}
	if ok {
		return bound, false, nil
	}

	beforeInsertHook(ctx)

	err = tx.QueryRow(ctx,
		`SELECT id FROM stores WHERE org_id = $1 AND provider = 'builtin' AND name = $2
		 AND owner_scope_level = $3 AND owner_scope_id = $4`,
		org, DefaultBuiltinStoreName, string(scope.Level), scope.ID,
	).Scan(&storeID)
	if errors.Is(err, pgx.ErrNoRows) {
		id, idErr := uuid.NewV7()
		if idErr != nil {
			return uuid.Nil, false, fmt.Errorf("catalog: generate store id: %w", idErr)
		}
		s, insErr := insertStoreTx(ctx, tx, id, org, "builtin", DefaultBuiltinStoreName, scope)
		if insErr != nil {
			return uuid.Nil, false, insErr
		}
		storeID, err = s.ID, nil
	}
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("catalog: lookup default store: %w", err)
	}
	if err := requireUsableStore(ctx, tx, org, []tenancy.Scope{scope}, storeID); err != nil {
		return uuid.Nil, false, err
	}
	bindingID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("catalog: generate store binding id: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO store_bindings (id, org_id, scope_level, scope_id, store_id) VALUES ($1, $2, $3, $4, $5)`,
		bindingID, org, string(scope.Level), scope.ID, storeID,
	); err != nil {
		if uniqueViolation(err) {
			return uuid.Nil, false, alreadyBoundError()
		}
		return uuid.Nil, false, fmt.Errorf("catalog: create default store binding: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, false, fmt.Errorf("catalog: commit ensure default store: %w", err)
	}
	return storeID, true, nil
}

// GetStore looks up a store by id, scoped to org — the read-side
// counterpart of [Catalog.CreateStore], for callers (internal/api's secret
// response) that only hold a secret's store_id, already found via a row this
// same org's caller was authorized to read, and need the store's own
// name/provider to render it.
//
// Unlike [storeNotUsableError]'s callers, id here is never caller-supplied —
// it comes from a secret row this org already owns, so pgx.ErrNoRows can
// only mean this database's own data is inconsistent (the store the secret
// points to is gone), never a caller mistake. An earlier version of this
// function answered ErrNoRows with storeNotUsableError() (400, "invalid
// argument") — the anti-oracle answer
// meant for a caller-named store id at bind time — telling an ordinary
// list/get-secret caller who supplied no store id at all that THEIR request
// was malformed. Any failure here is left unclassified, so writeAppError's
// default branch renders it the same opaque 500 a panic would.
func (c *Catalog) GetStore(ctx context.Context, org, id uuid.UUID) (Store, error) {
	var s Store
	err := c.pool.QueryRow(ctx,
		`SELECT id, org_id, provider, name, owner_scope_level, owner_scope_id, status, created_at
		 FROM stores WHERE org_id = $1 AND id = $2`,
		org, id,
	).Scan(&s.ID, &s.OrgID, &s.Provider, &s.Name, &s.OwnerScope.Level, &s.OwnerScope.ID, &s.Status, &s.CreatedAt)
	if err != nil {
		return Store{}, fmt.Errorf("catalog: get store: %w", err)
	}
	return s, nil
}

// storeBindingAt returns the store bound exactly at scope, if any.
func storeBindingAt(ctx context.Context, db dbtx, org uuid.UUID, scope tenancy.Scope) (uuid.UUID, bool, error) {
	var storeID uuid.UUID
	err := db.QueryRow(ctx,
		`SELECT store_id FROM store_bindings WHERE org_id = $1 AND scope_level = $2 AND scope_id = $3`,
		org, string(scope.Level), scope.ID,
	).Scan(&storeID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, false, nil
		}
		return uuid.Nil, false, fmt.Errorf("catalog: lookup store binding: %w", err)
	}
	return storeID, true, nil
}

// ResolveStore walks chain (target scope first, its ancestors up to and
// including org last — see [Chain]) and returns the first bound store it
// finds (tenancy model §3: the store for a new record is the StoreBinding of
// the scope the secret is created into, walked upward the same way). It
// reads through the pool; CreateRef, which needs this from inside its own
// transaction, calls [resolveStoreTx] instead.
func (c *Catalog) ResolveStore(ctx context.Context, org uuid.UUID, chain []tenancy.Scope) (uuid.UUID, error) {
	return resolveStoreTx(ctx, c.pool, org, chain)
}

func resolveStoreTx(ctx context.Context, db dbtx, org uuid.UUID, chain []tenancy.Scope) (uuid.UUID, error) {
	for _, s := range chain {
		id, ok, err := storeBindingAt(ctx, db, org, s)
		if err != nil {
			return uuid.Nil, err
		}
		if ok {
			return id, nil
		}
	}
	return uuid.Nil, apperr.New(apperr.ClassNoStoreBound, "no store bound at this scope or any ancestor")
}

// requireUsableStore checks an explicitly chosen store for a new record: it
// must be active and owned by a scope in chain (the target scope and its
// ancestors up to the organisation). A store belongs to the scope that owns
// it (tenancy model §3: "a user's store is used only for secrets in that
// user's scope"), so a store owned anywhere else — a sibling user, another
// workspace — is not the caller's to point a reference at, even though the
// record only carries the store's id today: a runner will read the value
// through (store_id, provider_ref) later.
//
// It reads the store's row FOR SHARE: called from inside CreateRef's or
// CreateStoreBinding's own transaction, that blocks a concurrent writer of
// the SAME row (there is no store-mutating admin surface yet beyond the raw
// SQL the tests use, but this is the same discipline requireUsableStore's
// callers already need for the OverrideLock race — see scopelock.go) until
// this transaction commits, so "checked usable" cannot stop being true
// before "used" without the writer simply waiting its turn.
//
// Every refusal — no such store in this organisation, a store outside the
// chain, a disabled store — is the same [storeNotUsableError], so the
// answer does not tell a caller which stores exist or whose they are.
func requireUsableStore(ctx context.Context, db dbtx, org uuid.UUID, chain []tenancy.Scope, storeID uuid.UUID) error {
	var owner tenancy.Scope
	var status string
	err := db.QueryRow(ctx,
		`SELECT owner_scope_level, owner_scope_id, status FROM stores WHERE org_id = $1 AND id = $2 FOR SHARE`,
		org, storeID,
	).Scan(&owner.Level, &owner.ID, &status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return storeNotUsableError()
		}
		return fmt.Errorf("catalog: lookup store: %w", err)
	}
	if status != "active" {
		return storeNotUsableError()
	}
	for _, s := range chain {
		if s == owner {
			return nil
		}
	}
	return storeNotUsableError()
}
