package catalog

import (
	"errors"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/google/uuid"
)

func (f *fixture) storeRows() (stores, bindings int) {
	f.t.Helper()
	if err := f.pool.QueryRow(f.ctx,
		`SELECT (SELECT count(*) FROM stores WHERE org_id = $1), (SELECT count(*) FROM store_bindings WHERE org_id = $1)`,
		f.org.ID).Scan(&stores, &bindings); err != nil {
		f.t.Fatalf("count store rows: %v", err)
	}
	return stores, bindings
}

func (f *fixture) refAtOrg(name string) error {
	f.t.Helper()
	_, err := f.cat.CreateRef(f.ctx, CreateRefInput{
		Org: f.org.ID, Scope: tenancy.Org(f.org.ID), Name: name, Class: "dev", Type: "generic", ProviderRef: "builtin://default/" + name,
	})
	return err
}

// A new organization has no store: CreateRef is refused with
// no_store_bound. After EnsureDefaultBuiltinStore it succeeds, and a second
// call changes nothing.
func TestEnsureDefaultBuiltinStore_BindsOnceAndIsIdempotent(t *testing.T) {
	f := newFixture(t)
	if err := f.refAtOrg("before"); !hasClass(err, apperr.ClassNoStoreBound) {
		t.Fatalf("CreateRef before ensure: %v, want no_store_bound (red control)", err)
	}

	id, created, err := f.cat.EnsureDefaultBuiltinStore(f.ctx, f.org.ID)
	if err != nil || !created || id == uuid.Nil {
		t.Fatalf("first ensure: id=%v created=%v err=%v, want a new binding", id, created, err)
	}
	s, err := f.cat.GetStore(f.ctx, f.org.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	if s.Provider != "builtin" || s.Name != DefaultBuiltinStoreName || s.OwnerScope != tenancy.Org(f.org.ID) || s.Status != "active" {
		t.Errorf("store %+v, want active builtin %q owned by the org scope", s, DefaultBuiltinStoreName)
	}
	if got, err := f.cat.ResolveStore(f.ctx, f.org.ID, []tenancy.Scope{tenancy.Org(f.org.ID)}); err != nil || got != id {
		t.Errorf("org scope resolves to %v (err %v), want %v", got, err, id)
	}
	if err := f.refAtOrg("after"); err != nil {
		t.Fatalf("CreateRef after ensure: %v", err)
	}

	again, created, err := f.cat.EnsureDefaultBuiltinStore(f.ctx, f.org.ID)
	if err != nil || created || again != id {
		t.Fatalf("second ensure: id=%v created=%v err=%v, want the same store and no new binding", again, created, err)
	}
	if st, b := f.storeRows(); st != 1 || b != 1 {
		t.Errorf("stores=%d bindings=%d after two calls, want 1 and 1", st, b)
	}
}

// An org scope already bound, to whatever store, is left as it is.
func TestEnsureDefaultBuiltinStore_KeepsExistingBinding(t *testing.T) {
	f := newFixture(t)
	ext := f.mustExternalStore("vault-main", tenancy.Org(f.org.ID))
	f.mustBind(tenancy.Org(f.org.ID), ext)

	id, created, err := f.cat.EnsureDefaultBuiltinStore(f.ctx, f.org.ID)
	if err != nil || created || id != ext.ID {
		t.Fatalf("ensure: id=%v created=%v err=%v, want the bound store %v untouched", id, created, err, ext.ID)
	}
	if st, b := f.storeRows(); st != 1 || b != 1 {
		t.Errorf("stores=%d bindings=%d, want 1 and 1: nothing created", st, b)
	}
}

// A "default" store that exists without a binding is bound, not duplicated;
// a disabled one is refused, not bound.
func TestEnsureDefaultBuiltinStore_BindsExistingDefault(t *testing.T) {
	f := newFixture(t)
	s := f.mustStore(DefaultBuiltinStoreName, tenancy.Org(f.org.ID))
	f.mustExec(`UPDATE stores SET status = 'disabled' WHERE id = $1`, s.ID)
	if _, _, err := f.cat.EnsureDefaultBuiltinStore(f.ctx, f.org.ID); !hasClass(err, apperr.ClassInvalidArgument) {
		t.Fatalf("ensure with a disabled default store: %v, want the store refused", err)
	}
	if _, b := f.storeRows(); b != 0 {
		t.Fatalf("bindings=%d, want 0: a disabled store is never bound", b)
	}
	f.mustExec(`UPDATE stores SET status = 'active' WHERE id = $1`, s.ID)

	id, created, err := f.cat.EnsureDefaultBuiltinStore(f.ctx, f.org.ID)
	if err != nil || !created || id != s.ID {
		t.Fatalf("ensure: id=%v created=%v err=%v, want the existing store %v bound", id, created, err, s.ID)
	}
	if st, b := f.storeRows(); st != 1 || b != 1 {
		t.Errorf("stores=%d bindings=%d, want 1 and 1", st, b)
	}
}

func TestEnsureDefaultBuiltinStore_UnknownOrg(t *testing.T) {
	f := newFixture(t)
	if _, _, err := f.cat.EnsureDefaultBuiltinStore(f.ctx, uuid.New()); !hasClass(err, apperr.ClassNotFound) {
		t.Fatalf("unknown org: %v, want not_found", err)
	}
	if n := countAll(f, `SELECT count(*) FROM stores`); n != 0 {
		t.Errorf("stores=%d, want 0", n)
	}
}

func countAll(f *fixture, q string) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(f.ctx, q).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// The store and the binding are one transaction: when the binding cannot be
// written (here a concurrent binding lands first), the new store is not left
// behind either.
func TestEnsureDefaultBuiltinStore_StoreAndBindingAtomic(t *testing.T) {
	f := newFixture(t)
	ext := f.mustExternalStore("vault-race", tenancy.Org(f.org.ID))
	ctx := withBeforeInsertHook(f.ctx, func() {
		f.mustExec(`INSERT INTO store_bindings (id, org_id, scope_level, scope_id, store_id) VALUES ($1, $2, 'org', $2, $3)`,
			uuid.New(), f.org.ID, ext.ID)
	})
	_, _, err := f.cat.EnsureDefaultBuiltinStore(ctx, f.org.ID)
	if !hasClass(err, apperr.ClassAlreadyExists) {
		t.Fatalf("ensure with a binding written underneath: %v, want already_exists", err)
	}
	var n int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM stores WHERE org_id = $1 AND name = $2`, f.org.ID, DefaultBuiltinStoreName).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d default store(s) left without a binding, want 0: store and binding must commit together", n)
	}
}

// Two concurrent calls for one org: the second waits for the first and
// finds its binding, instead of racing it into a duplicate store.
func TestEnsureDefaultBuiltinStore_ConcurrentCallsSerialized(t *testing.T) {
	f := newFixture(t)
	reached, proceed := make(chan struct{}), make(chan struct{})
	paused := withBeforeInsertHook(f.ctx, func() {
		close(reached)
		<-proceed
	})
	type result struct {
		id      uuid.UUID
		created bool
		err     error
	}
	first, second := make(chan result, 1), make(chan result, 1)
	go func() {
		id, c, err := f.cat.EnsureDefaultBuiltinStore(paused, f.org.ID)
		first <- result{id, c, err}
	}()
	if !awaitSignal(reached, 5*time.Second) {
		close(proceed)
		t.Fatal("first call never reached its beforeInsertHook")
	}
	go func() {
		id, c, err := f.cat.EnsureDefaultBuiltinStore(f.ctx, f.org.ID)
		second <- result{id, c, err}
	}()
	early := false
	select {
	case <-second:
		early = true
	case <-time.After(150 * time.Millisecond):
	}
	close(proceed)
	r1 := <-first
	if early {
		t.Fatalf("second call finished while the first was in flight: the organization row is not held (first: %v)", r1.err)
	}
	r2 := <-second
	if r1.err != nil || r2.err != nil {
		t.Fatalf("first err %v, second err %v; want both to succeed", r1.err, r2.err)
	}
	if !r1.created || r2.created || r1.id != r2.id {
		t.Errorf("first (%v, created=%v), second (%v, created=%v); want one binding, shared", r1.id, r1.created, r2.id, r2.created)
	}
	if st, b := f.storeRows(); st != 1 || b != 1 {
		t.Errorf("stores=%d bindings=%d, want 1 and 1", st, b)
	}
}

func hasClass(err error, class apperr.Class) bool {
	var ae *apperr.Error
	return errors.As(err, &ae) && ae.Class == class
}
