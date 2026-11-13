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

// UpgradeStore turns a store installation into an extension only through a
// live window of the same organisation; each refusal leaves the window and
// the installation as they were.
func TestUpgradeStoreRefusals(t *testing.T) {
	f := newSyncFixture(t)
	org := f.org(t)
	sealed := 0
	seal := func(context.Context) error { sealed++; return nil }
	windows := func(ws uuid.UUID) int {
		var n int
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM mesh_pending_installs WHERE workspace_id=$1`, ws).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	open := func(ws uuid.UUID) Pending {
		p := Pending{Org: org, OpenedBy: uuid.New(), MeshURL: "https://mesh.example.test", SecretSHA256: strings.Repeat("cd", 32)}
		if _, err := f.repo.OpenPending(f.ctx, ws, p); err != nil {
			t.Fatalf("open window: %v", err)
		}
		return p
	}
	store := func() uuid.UUID {
		ws := uuid.New()
		if err := f.repo.Upsert(f.ctx, org, ws, uuid.New(), "https://mesh.example.test", ModeStore); err != nil {
			t.Fatal(err)
		}
		return ws
	}

	ws := store()
	p := open(ws)
	if err := f.repo.UpgradeStore(f.ctx, ws, p, seal); err != nil || sealed != 1 || f.mode(t, ws) != "extension" || windows(ws) != 0 {
		t.Fatalf("positive control: err=%v sealed=%d mode=%s windows=%d", err, sealed, f.mode(t, ws), windows(ws))
	}

	// An extension installation is never replaced, whatever window exists.
	ext := f.ws
	p = open(ext)
	sealed = 0
	if err := f.repo.UpgradeStore(f.ctx, ext, p, seal); !errors.Is(err, ErrNotStore) || sealed != 0 || windows(ext) != 1 || f.mode(t, ext) != "extension" {
		t.Fatalf("extension: err=%v sealed=%d windows=%d", err, sealed, windows(ext))
	}

	// A window naming another Mesh would redirect the sealed token: refused.
	ws = store()
	p = open(ws)
	other := p
	other.MeshURL = "https://mesh.attacker.test"
	if _, err := f.pool.Exec(f.ctx, `UPDATE mesh_pending_installs SET mesh_url=$2 WHERE workspace_id=$1`, ws, other.MeshURL); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.UpgradeStore(f.ctx, ws, other, seal); !errors.Is(err, ErrNotStore) || windows(ws) != 1 || f.mode(t, ws) != "store" || sealed != 0 {
		t.Fatalf("other mesh_url: err=%v windows=%d mode=%s sealed=%d", err, windows(ws), f.mode(t, ws), sealed)
	}

	// A window of another organisation consumes nothing.
	ws = store()
	p = open(ws)
	foreign := p
	foreign.Org = uuid.New()
	if err := f.repo.UpgradeStore(f.ctx, ws, foreign, seal); !errors.Is(err, ErrNoWindow) || windows(ws) != 1 || f.mode(t, ws) != "store" {
		t.Fatalf("foreign org: err=%v windows=%d mode=%s", err, windows(ws), f.mode(t, ws))
	}

	// An expired window consumes nothing, even if the caller still holds it.
	if _, err := f.pool.Exec(f.ctx, `UPDATE mesh_pending_installs SET expires_at = now() - interval '1 minute' WHERE workspace_id=$1`, ws); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.UpgradeStore(f.ctx, ws, p, seal); !errors.Is(err, ErrNoWindow) || f.mode(t, ws) != "store" || sealed != 0 {
		t.Fatalf("expired: err=%v mode=%s sealed=%d", err, f.mode(t, ws), sealed)
	}

	// A store installation of another organisation is not the window's to
	// upgrade, and the window stays.
	ws = uuid.New()
	rival := uuid.New()
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO organizations(id,name) VALUES($1,'rival')`, rival); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.Upsert(f.ctx, rival, ws, uuid.New(), "https://mesh.example.test", ModeStore); err != nil {
		t.Fatal(err)
	}
	// OpenPending refuses this workspace, so the window row is written directly.
	p = Pending{Org: org, OpenedBy: uuid.New(), MeshURL: "https://mesh.example.test", SecretSHA256: strings.Repeat("cd", 32)}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO mesh_pending_installs (workspace_id, org_id, opened_by, mesh_url, secret_sha256, expires_at) VALUES ($1,$2,$3,$4,$5, now() + interval '10 minutes')`, ws, p.Org, p.OpenedBy, p.MeshURL, p.SecretSHA256); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.UpgradeStore(f.ctx, ws, p, seal); !errors.Is(err, ErrNotStore) || windows(ws) != 1 || f.mode(t, ws) != "store" || sealed != 0 {
		t.Fatalf("installation of another org: err=%v windows=%d mode=%s sealed=%d", err, windows(ws), f.mode(t, ws), sealed)
	}

	// A caller that holds another digest or another opener consumes nothing.
	ws = store()
	p = open(ws)
	wrong := p
	wrong.SecretSHA256 = strings.Repeat("ef", 32)
	if err := f.repo.UpgradeStore(f.ctx, ws, wrong, seal); !errors.Is(err, ErrNoWindow) || windows(ws) != 1 || f.mode(t, ws) != "store" || sealed != 0 {
		t.Fatalf("other digest: err=%v windows=%d mode=%s sealed=%d", err, windows(ws), f.mode(t, ws), sealed)
	}
	wrong = p
	wrong.OpenedBy = uuid.New()
	if err := f.repo.UpgradeStore(f.ctx, ws, wrong, seal); !errors.Is(err, ErrNoWindow) || windows(ws) != 1 || f.mode(t, ws) != "store" || sealed != 0 {
		t.Fatalf("other opener: err=%v windows=%d mode=%s sealed=%d", err, windows(ws), f.mode(t, ws), sealed)
	}

	// A failing seal rolls the window and the mode back.
	ws = store()
	p = open(ws)
	boom := errors.New("seal failed")
	if err := f.repo.UpgradeStore(f.ctx, ws, p, func(context.Context) error { return boom }); !errors.Is(err, boom) || windows(ws) != 1 || f.mode(t, ws) != "store" {
		t.Fatalf("failed seal: err=%v windows=%d mode=%s", err, windows(ws), f.mode(t, ws))
	}
}
