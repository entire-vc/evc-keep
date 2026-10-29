package meshext

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/store"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// cursorFetcher is a Mesh that never changes: it answers 304 to any cursor and
// the same snapshot to a fetch without one. It records the ETags it was sent.
type cursorFetcher struct {
	mu    sync.Mutex
	ws    uuid.UUID
	users []uuid.UUID
	fail  bool
	etags []string
}

func (f *cursorFetcher) FetchHierarchy(_ context.Context, _, _ uuid.UUID, _, etag string) (Fetched, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.etags = append(f.etags, etag)
	if f.fail {
		return Fetched{}, errors.New("unreachable")
	}
	if etag != "" {
		return Fetched{NotModified: true}, nil
	}
	members := make([]map[string]any, 0, len(f.users))
	for _, u := range f.users {
		members = append(members, map[string]any{"user_id": u, "role": "member"})
	}
	body, err := json.Marshal(map[string]any{"workspace": map[string]any{"id": f.ws}, "members": members})
	if err != nil {
		return Fetched{}, err
	}
	return Fetched{ETag: `"c1"`, Body: body}, nil
}

func (f *cursorFetcher) lastETag() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.etags) == 0 {
		return "<none>"
	}
	return f.etags[len(f.etags)-1]
}

type syncFixture struct {
	ctx  context.Context
	pool *pgxpool.Pool
	repo *Repo
	ws   uuid.UUID
}

func newSyncFixture(t *testing.T) *syncFixture {
	t.Helper()
	dsn := pgscratch.New(t, nil)
	ctx := context.Background()
	mdb, err := store.OpenMigrationDB(ctx, dsn)
	if err != nil {
		t.Fatal("open migration database")
	}
	defer func() { _ = mdb.Close() }()
	provider, err := store.NewProvider(mdb)
	if err != nil {
		t.Fatal("new migration provider")
	}
	if _, err = provider.Up(ctx); err != nil {
		t.Fatal("migrate test database")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("open test pool")
	}
	t.Cleanup(pool.Close)
	f := &syncFixture{ctx: ctx, pool: pool, repo: NewRepo(pool), ws: uuid.New()}
	org := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO organizations(id,name) VALUES($1,'sync')`, org); err != nil {
		t.Fatal("insert organization")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO mesh_installations(workspace_id,org_id,mesh_url,installed_by) VALUES($1,$2,'https://mesh.example.test',$3)`, f.ws, org, uuid.New()); err != nil {
		t.Fatal("insert installation")
	}
	return f
}

func (f *syncFixture) member(t *testing.T, user uuid.UUID) string {
	t.Helper()
	var s string
	if err := f.pool.QueryRow(f.ctx, `SELECT status FROM mesh_members WHERE workspace_id=$1 AND user_id=$2`, f.ws, user).Scan(&s); err != nil {
		t.Fatalf("member status: %v", err)
	}
	return s
}

func (f *syncFixture) state(t *testing.T) (result string, fullAt *time.Time) {
	t.Helper()
	if err := f.pool.QueryRow(f.ctx, `SELECT last_result, last_full_sync_at FROM mesh_sync_state WHERE workspace_id=$1`, f.ws).Scan(&result, &fullAt); err != nil {
		t.Fatalf("sync state: %v", err)
	}
	return result, fullAt
}

// ageFullSync moves the last full fetch back by d.
func (f *syncFixture) ageFullSync(t *testing.T, d time.Duration) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, `UPDATE mesh_sync_state SET last_full_sync_at = last_full_sync_at - make_interval(secs => $2) WHERE workspace_id=$1`, f.ws, d.Seconds()); err != nil {
		t.Fatalf("age full sync: %v", err)
	}
}

// diverge breaks Keep's mirror while Mesh stays unchanged: a member is deleted
// and a row Mesh never reported is added as active.
func (f *syncFixture) diverge(t *testing.T, deleted, foreign uuid.UUID) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, `DELETE FROM mesh_members WHERE workspace_id=$1 AND user_id=$2`, f.ws, deleted); err != nil {
		t.Fatalf("delete member: %v", err)
	}
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO mesh_members (workspace_id, user_id, role, status, state_at) VALUES ($1,$2,'member','active',now() - interval '1 second')`, f.ws, foreign); err != nil {
		t.Fatalf("insert foreign member: %v", err)
	}
}

// A divergence that exists only in Keep's mirror is invisible to the ETag: Mesh
// answers 304. Once FullSyncInterval has passed since the last full snapshot,
// the reconciliation drops the cursor and the full snapshot repairs it.
func TestReconcileFullFetchRepairsKeepSideDivergence(t *testing.T) {
	f := newSyncFixture(t)
	alice, bob, stranger := uuid.New(), uuid.New(), uuid.New()
	mesh := &cursorFetcher{ws: f.ws, users: []uuid.UUID{alice, bob}}

	if res, err := f.repo.Reconcile(f.ctx, mesh, f.ws); err != nil || res.NotModified || mesh.lastETag() != "" {
		t.Fatalf("first reconcile = %+v, %v, etag %q; want a full fetch", res, err, mesh.lastETag())
	}
	if _, fullAt := f.state(t); fullAt == nil {
		t.Fatal("a full snapshot did not record last_full_sync_at")
	}
	f.diverge(t, bob, stranger)

	// The defect as seen on production: within the interval the cursor is
	// trusted, Mesh answers 304 and the divergence stays.
	if res, err := f.repo.Reconcile(f.ctx, mesh, f.ws); err != nil || !res.NotModified || mesh.lastETag() != "c1" {
		t.Fatalf("reconcile within the interval = %+v, %v, etag %q; want not_modified on the cursor", res, err, mesh.lastETag())
	}
	if got := f.member(t, stranger); got != "active" {
		t.Fatalf("control: stranger = %s after a 304, want still active", got)
	}

	f.ageFullSync(t, FullSyncInterval+time.Second)
	res, err := f.repo.Reconcile(f.ctx, mesh, f.ws)
	if err != nil || res.NotModified {
		t.Fatalf("reconcile past the interval = %+v, %v; want a full snapshot", res, err)
	}
	if got := mesh.lastETag(); got != "" {
		t.Fatalf("fetch past the interval sent etag %q, want none", got)
	}
	if got := f.member(t, bob); got != "active" {
		t.Fatalf("deleted member = %s, want active again", got)
	}
	if got := f.member(t, stranger); got != "orphaned" {
		t.Fatalf("foreign member = %s, want orphaned", got)
	}
	result, fullAt := f.state(t)
	if result != "ok" || fullAt == nil || time.Since(*fullAt) > time.Minute {
		t.Fatalf("sync state = %q, %v; want ok with a fresh last_full_sync_at", result, fullAt)
	}

	// The fresh full fetch restarts the interval: the cursor is used again.
	if res, err := f.repo.Reconcile(f.ctx, mesh, f.ws); err != nil || !res.NotModified || mesh.lastETag() != "c1" {
		t.Fatalf("reconcile after the full fetch = %+v, %v, etag %q; want the cursor", res, err, mesh.lastETag())
	}
}

// Within the interval the stored cursor is sent, the round ends not_modified,
// and neither a 304 nor a failed fetch past the interval moves
// last_full_sync_at.
func TestReconcileKeepsCursorWhileFullSyncIsFresh(t *testing.T) {
	f := newSyncFixture(t)
	mesh := &cursorFetcher{ws: f.ws, users: []uuid.UUID{uuid.New()}}
	if _, err := f.repo.Reconcile(f.ctx, mesh, f.ws); err != nil {
		t.Fatal(err)
	}
	f.ageFullSync(t, FullSyncInterval/2)
	_, before := f.state(t)

	res, err := f.repo.Reconcile(f.ctx, mesh, f.ws)
	if err != nil || !res.NotModified {
		t.Fatalf("reconcile = %+v, %v; want not_modified", res, err)
	}
	if got := mesh.lastETag(); got != "c1" {
		t.Fatalf("fetch sent etag %q, want the stored cursor c1", got)
	}
	result, after := f.state(t)
	if result != "not_modified" || after == nil || !after.Equal(*before) {
		t.Fatalf("after a 304: %q, last_full_sync_at %v -> %v; want not_modified, unchanged", result, before, after)
	}

	f.ageFullSync(t, FullSyncInterval)
	_, before = f.state(t)
	mesh.fail = true
	if _, err := f.repo.Reconcile(f.ctx, mesh, f.ws); err == nil {
		t.Fatal("a failed fetch reported success")
	}
	if got := mesh.lastETag(); got != "" {
		t.Fatalf("due full fetch sent etag %q, want none", got)
	}
	result, after = f.state(t)
	if result != "failed" || after == nil || !after.Equal(*before) {
		t.Fatalf("after a failed fetch: %q, last_full_sync_at %v -> %v; want failed, unchanged", result, before, after)
	}
}

// Mesh sends workspace.member.added and workspace.member.removed with the same
// flat body ({workspace_id, user_id, role}): only X-Mesh-Event tells them
// apart and only X-Mesh-Delivery tells one send from the next. An id derived
// from the body alone made an added after a removed look like a repeat, and
// the event was dropped.
func TestParseEventFlatIDSeparatesEvents(t *testing.T) {
	ws, now := uuid.New(), time.Now()
	body, _ := json.Marshal(map[string]any{"workspace_id": ws, "user_id": uuid.New(), "role": "member"})
	id := func(b []byte, typ, delivery string) string {
		t.Helper()
		ev, err := ParseEvent(b, ws, now, typ, delivery)
		if err != nil {
			t.Fatalf("%s %q: %v", typ, delivery, err)
		}
		if !ValidEventID(ev.ID) {
			t.Fatalf("%s %q: id %q is not a valid event id", typ, delivery, ev.ID)
		}
		return ev.ID
	}
	const removed, added = "workspace.member.removed", "workspace.member.added"

	r1 := id(body, removed, "d-1")
	if a := id(body, added, "d-2"); a == r1 {
		t.Fatalf("added and removed with the same body share id %q", a)
	}
	// A second removed after the member came back is a new send.
	if r2 := id(body, removed, "d-3"); r2 == r1 {
		t.Fatalf("two sends of removed share id %q", r2)
	}
	// A retry of one send is the same event.
	if again := id(body, removed, "d-1"); again != r1 {
		t.Fatalf("retry of one delivery: id %q, want %q", again, r1)
	}
	// Without a delivery id the type still separates added from removed.
	if id(body, added, "") == id(body, removed, "") {
		t.Fatal("without a delivery id added and removed share an id")
	}
	// The known gap: same type, same body, no delivery id is one event.
	if a, b := id(body, removed, ""), id(body, removed, ""); a != b {
		t.Fatal("same type and body without a delivery id: ids differ")
	}
	// Another body under the same headers is another event.
	other, _ := json.Marshal(map[string]any{"workspace_id": ws, "user_id": uuid.New(), "role": "member"})
	if id(other, removed, "d-1") == r1 {
		t.Fatal("two bodies under the same headers share an id")
	}
}

// A gate answer is recognised by its signed fields, and its id comes from the
// signed body alone: editing either header of a replayed answer cannot make it
// a new event and run the answer twice.
func TestParseEventFlatGateIDIgnoresHeaders(t *testing.T) {
	ws, now := uuid.New(), time.Now()
	body, _ := json.Marshal(map[string]any{"workspace_id": ws, "task_id": uuid.NewString(), "decision": "approve",
		"decided_by": uuid.NewString(), "decided_by_type": "user", "external_hash": "h"})
	var first string
	for _, h := range [][2]string{{GateDecided, "d-1"}, {GateDecided, "d-2"}, {"project.created", "d-3"}, {"", ""}} {
		ev, err := ParseEvent(body, ws, now, h[0], h[1])
		if err != nil || ev.Type != GateDecided {
			t.Fatalf("headers %q: %+v, %v; want a gate answer", h, ev.Type, err)
		}
		if first == "" {
			first = ev.ID
		} else if ev.ID != first {
			t.Fatalf("headers %q: id %q, want %q", h, ev.ID, first)
		}
	}
}

// The type of a flat event comes from an unsigned header and a replay with
// edited headers gets a new id, so a flat hierarchy event must never apply: a
// stated time in the body is ignored and the event stays untimed.
func TestParseEventFlatHierarchyIsNeverTimed(t *testing.T) {
	ws, now := uuid.New(), time.Now()
	body, _ := json.Marshal(map[string]any{"workspace_id": ws, "user_id": uuid.New(), "role": "member",
		"occurred_at": now.Add(-time.Minute).UTC().Format(time.RFC3339Nano)})
	for _, typ := range []string{"workspace.member.added", "workspace.member.removed", "agent.key.revoked"} {
		ev, err := ParseEvent(body, ws, now, typ, "d-1")
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if ev.Timed {
			t.Fatalf("%s: a flat body with occurred_at is timed and would apply under an unsigned type", typ)
		}
	}
}
