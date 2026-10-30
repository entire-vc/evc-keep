package meshext

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// countFetcher counts the fetches per workspace and answers every one with a
// failure, so a fetch it was never asked for cannot go unnoticed.
type countFetcher struct {
	mu   sync.Mutex
	seen map[uuid.UUID]int
}

func (f *countFetcher) FetchHierarchy(_ context.Context, _, ws uuid.UUID, _, _ string) (Fetched, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen[ws]++
	return Fetched{}, errors.New("unauthorized")
}

func (f *syncFixture) mode(t *testing.T, ws uuid.UUID) string {
	t.Helper()
	var m string
	if err := f.pool.QueryRow(f.ctx, `SELECT mode FROM mesh_installations WHERE workspace_id=$1`, ws).Scan(&m); err != nil {
		t.Fatalf("installation mode: %v", err)
	}
	return m
}

func (f *syncFixture) org(t *testing.T) uuid.UUID {
	t.Helper()
	var org uuid.UUID
	if err := f.pool.QueryRow(f.ctx, `SELECT org_id FROM mesh_installations WHERE workspace_id=$1`, f.ws).Scan(&org); err != nil {
		t.Fatalf("installation org: %v", err)
	}
	return org
}

// A store-only installation has no Keep extension in its Mesh: the background
// reconciliation never calls Mesh for it and logs no failure for it, while an
// extension installation of the same organisation is still fetched and its
// failure still logged.
func TestReconcileAllSkipsStoreInstallations(t *testing.T) {
	f := newSyncFixture(t)
	store := uuid.New()
	if err := f.repo.Upsert(f.ctx, f.org(t), store, uuid.New(), "https://mesh.store.test", ModeStore); err != nil {
		t.Fatalf("store install: %v", err)
	}
	if got := f.mode(t, store); got != "store" {
		t.Fatalf("store install recorded mode %q", got)
	}
	var logs strings.Builder
	fetch := &countFetcher{seen: map[uuid.UUID]int{}}
	f.repo.ReconcileAll(f.ctx, fetch, slog.New(slog.NewTextHandler(&logs, nil)))
	if fetch.seen[f.ws] != 1 {
		t.Fatalf("extension installation fetched %d times, want 1", fetch.seen[f.ws])
	}
	if fetch.seen[store] != 0 {
		t.Fatalf("store installation fetched %d times, want 0", fetch.seen[store])
	}
	if !strings.Contains(logs.String(), "mesh reconcile failed") || !strings.Contains(logs.String(), f.ws.String()) {
		t.Fatal("the failing extension installation raised no warning")
	}
	if strings.Contains(logs.String(), store.String()) {
		t.Fatal("the store installation was named in the reconciliation log")
	}
}

// The install paths record the mode they are given, a reinstall records the
// one it states, and an unknown mode writes nothing.
func TestInstallRecordsExplicitMode(t *testing.T) {
	f := newSyncFixture(t)
	org, ws := f.org(t), uuid.New()
	for _, m := range []Mode{"", "both", "Store"} {
		if err := f.repo.Upsert(f.ctx, org, ws, uuid.New(), "https://mesh.example.test", m); !errors.Is(err, ErrBadMode) {
			t.Fatalf("Upsert with mode %q: %v", m, err)
		}
		if err := f.repo.BindPending(f.ctx, ws, Pending{Org: org}, m, func(context.Context) error { return nil }); !errors.Is(err, ErrBadMode) {
			t.Fatalf("BindPending with mode %q: %v", m, err)
		}
	}
	var n int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM mesh_installations WHERE workspace_id=$1`, ws).Scan(&n); err != nil || n != 0 {
		t.Fatalf("an unknown mode stored %d rows (%v)", n, err)
	}
	if err := f.repo.Upsert(f.ctx, org, ws, uuid.New(), "https://mesh.example.test", ModeStore); err != nil {
		t.Fatal(err)
	}
	if got := f.mode(t, ws); got != "store" {
		t.Fatalf("mode %q after a store install", got)
	}
	if err := f.repo.Upsert(f.ctx, org, ws, uuid.New(), "https://mesh.example.test", ModeExtension); err != nil {
		t.Fatal(err)
	}
	if got := f.mode(t, ws); got != "extension" {
		t.Fatalf("mode %q after an extension reinstall", got)
	}

	hs := uuid.New()
	p := Pending{Org: org, OpenedBy: uuid.New(), MeshURL: "https://mesh.example.test", SecretSHA256: strings.Repeat("ab", 32)}
	if _, err := f.repo.OpenPending(f.ctx, hs, p); err != nil {
		t.Fatalf("open window: %v", err)
	}
	if err := f.repo.BindPending(f.ctx, hs, p, ModeStore, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if got := f.mode(t, hs); got != "store" {
		t.Fatalf("BindPending recorded mode %q, want the one it was given", got)
	}
}

// A store-only installation is not an extension installation: nothing that
// calls Mesh with the actor token finds it, while Installation (used for the
// calls Mesh makes into Keep) still does.
func TestExtensionInstallationSkipsStore(t *testing.T) {
	f := newSyncFixture(t)
	org, ws := f.org(t), uuid.New()
	if err := f.repo.Upsert(f.ctx, org, ws, uuid.New(), "https://mesh.store.test", ModeStore); err != nil {
		t.Fatal(err)
	}
	if _, _, found, err := f.repo.ExtensionInstallation(f.ctx, ws); err != nil || found {
		t.Fatalf("store installation found as an extension: found=%v err=%v", found, err)
	}
	if got, _, found, err := f.repo.Installation(f.ctx, ws); err != nil || !found || got != org {
		t.Fatalf("store installation lost for Mesh's own calls: found=%v err=%v", found, err)
	}
	// Positive control: the extension installation of the fixture is found.
	if got, _, found, err := f.repo.ExtensionInstallation(f.ctx, f.ws); err != nil || !found || got != org {
		t.Fatalf("extension installation not found: found=%v err=%v", found, err)
	}
}
