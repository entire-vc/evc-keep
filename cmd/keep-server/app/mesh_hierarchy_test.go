package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/meshext"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// fakeMesh is the Mesh side of GET /workspaces/{ws}/export/hierarchy, a fake of
// the protocol only: Bearer check, ETag/If-None-Match, and a body shaped like
// Mesh's. It records what it was asked.
type fakeMesh struct {
	srv   *httptest.Server
	mu    sync.Mutex
	token string
	ws    uuid.UUID
	snap  map[string]any
	// failWith, when non-zero, answers that status with a body that echoes the
	// bearer token, the way a careless upstream error page might.
	failWith int
	// oversize, when set, answers 200 with a body past the fetch limit.
	oversize bool
	// redirectTo, when set, answers every request with a redirect there.
	redirectTo string
	// etagPad lengthens the ETag Mesh sends.
	etagPad string
	auth    []string
	inm     []string
	etagSeq int
}

func newFakeMesh(t *testing.T, ws uuid.UUID, token string) *fakeMesh {
	t.Helper()
	m := &fakeMesh{token: token, ws: ws}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.auth = append(m.auth, r.Header.Get("Authorization"))
		m.inm = append(m.inm, r.Header.Get("If-None-Match"))
		if r.URL.Path != "/api/v1/workspaces/"+ws.String()+"/export/hierarchy" {
			http.NotFound(w, r)
			return
		}
		if m.redirectTo != "" {
			http.Redirect(w, r, m.redirectTo, http.StatusFound)
			return
		}
		if m.oversize {
			_, _ = w.Write(make([]byte, 17<<20))
			return
		}
		if m.failWith != 0 {
			w.WriteHeader(m.failWith)
			_, _ = fmt.Fprintf(w, "upstream says: bad credential %s", r.Header.Get("Authorization")) // #nosec G705 -- test fake echoing a canary to a recorder, no browser
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+m.token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, _ := json.Marshal(m.snap)
		etag := fmt.Sprintf(`"c%d-%d%s"`, m.etagSeq, len(raw), m.etagPad)
		if r.Header.Get("If-None-Match") == etag {
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write(raw)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *fakeMesh) set(snap map[string]any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snap = snap
	m.etagSeq++
}

func (m *fakeMesh) lastInm() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inm[len(m.inm)-1]
}

func (m *fakeMesh) requests() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.auth)
}

func hierarchy(ws uuid.UUID, members, projects []uuid.UUID, agents map[uuid.UUID][]string, prefix string) map[string]any {
	ms := []map[string]any{}
	for _, u := range members {
		ms = append(ms, map[string]any{"user_id": u, "email": u.String() + "@example.test", "name": "n", "role": "member"})
	}
	ps := []map[string]any{}
	for _, p := range projects {
		ps = append(ps, map[string]any{"id": p, "slug": "p-" + p.String()[:4], "name": "P", "is_archived": false})
	}
	as := []map[string]any{}
	for a, keys := range agents {
		ks := []map[string]any{}
		for _, k := range keys {
			ks = append(ks, map[string]any{"key_id": k, "key_prefix": prefix, "label": "l"})
		}
		as = append(as, map[string]any{"id": a, "slug": "a-" + a.String()[:4], "sponsor_user_id": nil, "active_keys": ks})
	}
	return map[string]any{"workspace": map[string]any{"id": ws, "slug": "w", "name": "W"}, "projects": ps, "members": ms, "agents": as}
}

// installAt connects ws with the fake Mesh as its URL and returns the events secret.
func (f *meshFixture) installAt(ws uuid.UUID, meshURL, token string) string {
	f.t.Helper()
	evSecret := "events-secret-" + uuid.NewString()
	b, _ := json.Marshal(map[string]string{
		"mesh_url": meshURL, "workspace_id": ws.String(),
		"extension_token": token, "events_endpoint_secret": evSecret,
	})
	installedKeepSecret(f.t, f.post("/mesh/install", f.admin, b, nil))
	return evSecret
}

func (f *meshFixture) status(table, idCol string, ws, id uuid.UUID) string {
	f.t.Helper()
	var s string
	err := f.pool.QueryRow(context.Background(), fmt.Sprintf(`SELECT status FROM %s WHERE workspace_id=$1 AND %s=$2`, table, idCol), ws, id).Scan(&s)
	if err != nil {
		return "absent"
	}
	return s
}

func (f *meshFixture) countRows(table string, ws uuid.UUID) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), fmt.Sprintf(`SELECT count(*) FROM %s WHERE workspace_id=$1`, table), ws).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *meshFixture) sendEvent(ws uuid.UUID, secret string, ev map[string]any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(ev)
	return f.post("/mesh/events", "", b, signedHeaders(ws, secret, time.Now(), b))
}

// reconciler builds the real fetcher over the fixture's vault and a logger
// that writes into the fixture's log buffer.
func (f *meshFixture) reconcile(ws uuid.UUID) (meshext.ReconcileResult, error) {
	return f.repo.Reconcile(context.Background(), f.fetcher, ws)
}

func TestMeshReconcileOrphansWhatMeshNoLongerReports(t *testing.T) {
	f := newMeshFixture(t, true)
	ws, token := uuid.New(), "tok-"+uuid.NewString()
	mesh := newFakeMesh(t, ws, token)
	f.installAt(ws, mesh.srv.URL, token)
	alice, bob, proj, agent, gone := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mesh.set(hierarchy(ws, []uuid.UUID{alice, bob}, []uuid.UUID{proj}, map[uuid.UUID][]string{agent: {"k1", "k2"}, gone: {"k3"}}, "pfx"))

	if res, err := f.reconcile(ws); err != nil || res.Orphaned != 0 || res.NotModified {
		t.Fatalf("first reconcile = %+v, %v", res, err)
	}
	for table, id := range map[string][2]any{
		"mesh_members": {"user_id", bob}, "mesh_projects": {"project_id", proj}, "mesh_agents": {"agent_id", agent},
	} {
		if got := f.status(table, id[0].(string), ws, id[1].(uuid.UUID)); got != "active" {
			t.Fatalf("%s after first sync = %s, want active", table, got)
		}
	}
	rowsBefore := f.countRows("mesh_members", ws) + f.countRows("mesh_projects", ws) + f.countRows("mesh_agents", ws) + f.countRows("mesh_agent_keys", ws)

	// The divergence: Mesh removed bob, the project, an agent with its key k3,
	// and key k2; keys of the agent that remains are k1 only.
	mesh.set(hierarchy(ws, []uuid.UUID{alice}, nil, map[uuid.UUID][]string{agent: {"k1"}}, "pfx"))
	// Red control: before any reconciliation Keep still shows bob as active.
	if got := f.status("mesh_members", "user_id", ws, bob); got != "active" {
		t.Fatalf("control: bob = %s before the sync, want active", got)
	}
	res, err := f.reconcile(ws)
	if err != nil || res.Orphaned != 5 {
		t.Fatalf("second reconcile = %+v, %v; want 5 orphaned (member, project, agent, two keys)", res, err)
	}
	if got := f.status("mesh_agents", "agent_id", ws, gone); got != "orphaned" {
		t.Fatalf("vanished agent = %s, want orphaned", got)
	}
	if got := f.status("mesh_agents", "agent_id", ws, agent); got != "active" {
		t.Fatalf("remaining agent = %s, want active", got)
	}
	if got := f.status("mesh_members", "user_id", ws, bob); got != "orphaned" {
		t.Fatalf("bob = %s, want orphaned", got)
	}
	if got := f.status("mesh_members", "user_id", ws, alice); got != "active" {
		t.Fatalf("alice = %s, want active", got)
	}
	if got := f.status("mesh_projects", "project_id", ws, proj); got != "orphaned" {
		t.Fatalf("project = %s, want orphaned", got)
	}
	var k2 string
	if err := f.pool.QueryRow(context.Background(), `SELECT status FROM mesh_agent_keys WHERE workspace_id=$1 AND key_id='k2'`, ws).Scan(&k2); err != nil || k2 != "orphaned" {
		t.Fatalf("key k2 = %q, %v; want orphaned", k2, err)
	}
	// Nothing was deleted.
	if rowsAfter := f.countRows("mesh_members", ws) + f.countRows("mesh_projects", ws) + f.countRows("mesh_agents", ws) + f.countRows("mesh_agent_keys", ws); rowsAfter != rowsBefore {
		t.Fatalf("rows %d -> %d: a sync deleted something", rowsBefore, rowsAfter)
	}
	// Bob coming back revives him.
	mesh.set(hierarchy(ws, []uuid.UUID{alice, bob}, []uuid.UUID{proj}, map[uuid.UUID][]string{agent: {"k1", "k2"}}, "pfx"))
	if _, err := f.reconcile(ws); err != nil {
		t.Fatal(err)
	}
	if got := f.status("mesh_members", "user_id", ws, bob); got != "active" {
		t.Fatalf("bob after return = %s, want active", got)
	}
}

func TestMeshReconcileUsesCursorAndEventsForceFullFetch(t *testing.T) {
	f := newMeshFixture(t, true)
	ws, token := uuid.New(), "tok-"+uuid.NewString()
	mesh := newFakeMesh(t, ws, token)
	evSecret := f.installAt(ws, mesh.srv.URL, token)
	mesh.set(hierarchy(ws, []uuid.UUID{uuid.New()}, nil, nil, "p"))

	if _, err := f.reconcile(ws); err != nil {
		t.Fatal(err)
	}
	if got := mesh.lastInm(); got != "" {
		t.Fatalf("first fetch sent If-None-Match %q", got)
	}
	res, err := f.reconcile(ws)
	if err != nil || !res.NotModified || mesh.lastInm() == "" {
		t.Fatalf("unchanged snapshot: %+v, %v, If-None-Match=%q; want NotModified with the cursor sent", res, err, mesh.lastInm())
	}
	// An event Keep cannot apply by itself (no data) makes the next fetch full,
	// even though Mesh's cursor is unchanged.
	if rec := f.sendEvent(ws, evSecret, map[string]any{"id": "e-nodata", "type": "project.updated", "workspace_id": ws.String()}); rec.Code != http.StatusOK {
		t.Fatalf("event: %d %s", rec.Code, answerDiag(rec))
	}
	res, err = f.reconcile(ws)
	if err != nil || res.NotModified || mesh.lastInm() != "" {
		t.Fatalf("after a data-less event: %+v, %v, If-None-Match=%q; want a full fetch", res, err, mesh.lastInm())
	}
	if res, err = f.reconcile(ws); err != nil || !res.NotModified {
		t.Fatalf("after the full fetch the cursor must be used again: %+v, %v", res, err)
	}
}

func TestMeshFailedFetchChangesNothing(t *testing.T) {
	f := newMeshFixture(t, true)
	ws, token := uuid.New(), "tok-"+uuid.NewString()
	mesh := newFakeMesh(t, ws, token)
	f.installAt(ws, mesh.srv.URL, token)
	bob := uuid.New()
	mesh.set(hierarchy(ws, []uuid.UUID{bob}, nil, nil, "p"))
	if _, err := f.reconcile(ws); err != nil {
		t.Fatal(err)
	}
	classes := map[int]string{500: "server", 401: "unauthorized", 403: "unauthorized", 418: "bad_status", 404: "not_found"}
	for _, code := range []int{500, 401, 403, 418, 404} {
		mesh.mu.Lock()
		mesh.failWith = code
		mesh.mu.Unlock()
		if _, err := f.reconcile(ws); err == nil {
			t.Fatalf("status %d: reconcile succeeded", code)
		}
		var got string
		if err := f.pool.QueryRow(context.Background(), `SELECT last_error_class FROM mesh_sync_state WHERE workspace_id=$1`, ws).Scan(&got); err != nil || got != classes[code] {
			t.Fatalf("status %d: error class %q, %v; want %q", code, got, err, classes[code])
		}
		if got := f.status("mesh_members", "user_id", ws, bob); got != "active" {
			t.Fatalf("status %d: an unreachable Mesh orphaned bob (%s)", code, got)
		}
	}
	// A body past the limit is refused as too_large, not read to the end.
	mesh.mu.Lock()
	mesh.failWith, mesh.oversize = 0, true
	mesh.mu.Unlock()
	if _, err := f.reconcile(ws); err == nil {
		t.Fatal("an oversized body was accepted")
	}
	if got := f.status("mesh_members", "user_id", ws, bob); got != "active" {
		t.Fatalf("an oversized body orphaned bob (%s)", got)
	}
	var result, class string
	if err := f.pool.QueryRow(context.Background(), `SELECT last_result, last_error_class FROM mesh_sync_state WHERE workspace_id=$1`, ws).Scan(&result, &class); err != nil || result != "failed" || class != "too_large" {
		t.Fatalf("sync state = %q/%q, %v; want failed/too_large", result, class, err)
	}
	// A snapshot for another workspace is refused without touching anything.
	mesh.mu.Lock()
	mesh.failWith, mesh.oversize = 0, false
	mesh.mu.Unlock()
	mesh.set(hierarchy(uuid.New(), nil, nil, nil, "p"))
	if _, err := f.reconcile(ws); err == nil {
		t.Fatal("a snapshot of another workspace was accepted")
	}
	if got := f.status("mesh_members", "user_id", ws, bob); got != "active" {
		t.Fatalf("a foreign snapshot orphaned bob (%s)", got)
	}
}

func TestMeshEventsApplyIdempotentlyAndInAnyOrder(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := uuid.New()
	evSecret := f.installAt(ws, "https://mesh.example.test", "tok-"+uuid.NewString())
	user, proj, agent := uuid.New(), uuid.New(), uuid.New()
	t1, t2 := time.Now().Add(-time.Minute).UTC(), time.Now().UTC()
	ev := func(id, typ string, at time.Time, data map[string]any) map[string]any {
		return map[string]any{"id": id, "type": typ, "workspace_id": ws.String(), "occurred_at": at.Format(time.RFC3339Nano), "data": data}
	}
	added := ev("m-add", "workspace.member.added", t1, map[string]any{"user_id": user, "role": "admin"})
	removed := ev("m-rem", "workspace.member.removed", t2, map[string]any{"user_id": user})
	// Delivered out of order and twice: the removal (newer) wins, the late add is ignored.
	for _, e := range []map[string]any{removed, added, removed, added} {
		if rec := f.sendEvent(ws, evSecret, e); rec.Code != http.StatusOK {
			t.Fatalf("event %v: %d %s", e["id"], rec.Code, answerDiag(rec))
		}
	}
	if got := f.status("mesh_members", "user_id", ws, user); got != "removed" {
		t.Fatalf("member = %s after removed(t2) then added(t1), want removed", got)
	}
	if n := f.countRows("mesh_members", ws); n != 1 {
		t.Fatalf("member rows = %d, want 1", n)
	}
	if n := f.eventRows(ws); n != 2 {
		t.Fatalf("event rows = %d, want 2 (a repeat is not a new event)", n)
	}
	// Re-added later: back to active.
	if rec := f.sendEvent(ws, evSecret, ev("m-add2", "workspace.member.added", time.Now().UTC(), map[string]any{"user_id": user})); rec.Code != http.StatusOK {
		t.Fatal(answerDiag(rec))
	}
	if got := f.status("mesh_members", "user_id", ws, user); got != "active" {
		t.Fatalf("member = %s after a newer add, want active", got)
	}

	for _, e := range []map[string]any{
		ev("p-1", "project.created", t1, map[string]any{"project_id": proj, "slug": "alpha", "name": "Alpha"}),
		ev("k-1", "agent.key.issued", t1, map[string]any{"agent_id": agent, "key_id": "key-1", "label": "ci", "sponsor_user_id": user}),
		ev("k-2", "agent.key.revoked", t2, map[string]any{"agent_id": agent, "key_id": "key-1"}),
		ev("k-1", "agent.key.issued", t1, map[string]any{"agent_id": agent, "key_id": "key-1"}), // replay of the issue
		ev("k-3", "agent.key.issued", t1, map[string]any{"agent_id": agent, "key_id": "key-1"}), // a late, older issue under a new id
	} {
		if rec := f.sendEvent(ws, evSecret, e); rec.Code != http.StatusOK {
			t.Fatalf("event %v: %d %s", e["id"], rec.Code, answerDiag(rec))
		}
	}
	if got := f.status("mesh_projects", "project_id", ws, proj); got != "active" {
		t.Fatalf("project = %s, want active", got)
	}
	var keyStatus string
	if err := f.pool.QueryRow(context.Background(), `SELECT status FROM mesh_agent_keys WHERE workspace_id=$1 AND key_id='key-1'`, ws).Scan(&keyStatus); err != nil || keyStatus != "revoked" {
		t.Fatalf("key = %q, %v; want revoked", keyStatus, err)
	}
	// Malformed data is refused and recorded nowhere.
	before := f.eventRows(ws)
	for name, e := range map[string]map[string]any{
		"future occurred_at": ev("bad-1", "project.updated", time.Now().Add(time.Hour), map[string]any{"project_id": proj}),
		"bad key id":         ev("bad-2", "agent.key.issued", t1, map[string]any{"agent_id": agent, "key_id": "bad key id"}),
		"role too long":      ev("bad-3", "workspace.member.added", t1, map[string]any{"user_id": user, "role": strings.Repeat("r", 65)}),
	} {
		if rec := f.sendEvent(ws, evSecret, e); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
	}
	if f.eventRows(ws) != before {
		t.Fatal("a refused event was recorded")
	}
}

// Leak test (written before the feature): the Mesh actor token must not be on
// any surface of the hierarchy sync, and no agent key material (not even the
// public prefix Mesh exports) may be stored. The upstream's own error page
// echoes the bearer; that must not reach a log, an error or a row either.
func TestMeshHierarchySyncNeverLeaksTokenOrKeys(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	if !c.In("x"+c.Value(1)) || !c.In(fmt.Sprintf("%x", c.Value(1))) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	token, prefix := c.Value(1), c.Value(2)
	ws := uuid.New()
	mesh := newFakeMesh(t, ws, token)
	evSecret := f.installAt(ws, mesh.srv.URL, token)
	agent := uuid.New()
	mesh.set(hierarchy(ws, []uuid.UUID{uuid.New()}, []uuid.UUID{uuid.New()}, map[uuid.UUID][]string{agent: {"k1"}}, prefix))

	var surfaces []string
	if _, err := f.reconcile(ws); err != nil {
		t.Fatal(err)
	}
	// Positive control: the fetch really carried the token, so the absence below means something.
	if mesh.requests() == 0 || mesh.auth[0] != "Bearer "+token {
		t.Fatal("the fake Mesh never saw the token; the leak check proves nothing")
	}
	for _, code := range []int{500, 401, 502} {
		mesh.mu.Lock()
		mesh.failWith = code
		mesh.mu.Unlock()
		_, err := f.reconcile(ws)
		if err == nil {
			t.Fatalf("status %d: no error", code)
		}
		surfaces = append(surfaces, err.Error(), fmt.Sprintf("%v %+v %#v", err, err, err))
	}
	mesh.mu.Lock()
	mesh.failWith = 0
	mesh.mu.Unlock()
	f.repo.ReconcileAll(context.Background(), f.fetcher, f.logger)
	mesh.mu.Lock()
	mesh.failWith = 500
	mesh.mu.Unlock()
	f.repo.ReconcileAll(context.Background(), f.fetcher, f.logger)
	// An event that carries the canaries in unknown data fields: they must not be stored.
	rec := f.sendEvent(ws, evSecret, map[string]any{"id": "e-leak", "type": "agent.key.issued", "workspace_id": ws.String(),
		"data": map[string]any{"agent_id": agent, "key_id": "k9", "label": "l", "key_prefix": prefix, "token": token}})
	surfaces = append(surfaces, rec.Body.String())

	ctx := context.Background()
	for _, table := range []string{"mesh_installations", "mesh_events", "mesh_members", "mesh_projects", "mesh_agents", "mesh_agent_keys", "mesh_sync_state", "audit_records"} {
		rows, err := f.pool.Query(ctx, `SELECT row_to_json(t)::text FROM `+table+` t`)
		if err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		n := 0
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			surfaces = append(surfaces, s)
			n++
		}
		rows.Close()
		if table != "audit_records" && table != "mesh_events" && n == 0 {
			t.Fatalf("%s is empty; the sync stored nothing and the check proves nothing", table)
		}
	}
	if f.logbuf.Len() == 0 {
		t.Fatal("logger captured nothing; the log check proves nothing")
	}
	surfaces = append(surfaces, f.logbuf.String())
	for i, s := range surfaces {
		if c.In(s) {
			t.Fatalf("token or key material on surface #%d (%d bytes); the surface is not printed", i, len(s))
		}
	}
}

// A redirect would carry the Authorization header to whatever host answers: the
// fetch must stop at it, and the token must reach only the installed Mesh URL.
func TestMeshFetchDoesNotFollowRedirectsWithToken(t *testing.T) {
	f := newMeshFixture(t, true)
	ws, token := uuid.New(), "tok-"+uuid.NewString()
	elsewhere := newFakeMesh(t, ws, token)
	elsewhere.set(hierarchy(ws, nil, nil, nil, "p"))
	mesh := newFakeMesh(t, ws, token)
	mesh.redirectTo = elsewhere.srv.URL + "/api/v1/workspaces/" + ws.String() + "/export/hierarchy"
	f.installAt(ws, mesh.srv.URL, token)
	if _, err := f.reconcile(ws); err == nil {
		t.Fatal("a redirect was treated as a snapshot")
	}
	if n := elsewhere.requests(); n != 0 {
		t.Fatalf("the redirect target received %d request(s) with the token", n)
	}
}

// One poisonous value must not freeze the mirror: PostgreSQL text cannot hold a
// NUL byte, so it is refused up front instead of failing to store forever, and
// a cursor too long to store is dropped instead of failing the sync.
func TestMeshPoisonousValuesDoNotFreezeTheMirror(t *testing.T) {
	f := newMeshFixture(t, true)
	ws, token := uuid.New(), "tok-"+uuid.NewString()
	mesh := newFakeMesh(t, ws, token)
	evSecret := f.installAt(ws, mesh.srv.URL, token)
	proj := uuid.New()
	rec := f.sendEvent(ws, evSecret, map[string]any{"id": "e-nul", "type": "project.created", "workspace_id": ws.String(),
		"data": map[string]any{"project_id": proj, "name": "bad\u0000name"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("event with a NUL byte: %d %s, want 400", rec.Code, answerDiag(rec))
	}
	bob := uuid.New()
	mesh.set(hierarchy(ws, []uuid.UUID{bob}, []uuid.UUID{proj}, nil, "p"))
	snap := mesh.snap
	snap["projects"].([]map[string]any)[0]["name"] = "bad\u0000name"
	if _, err := f.reconcile(ws); err == nil {
		t.Fatal("a snapshot with a NUL byte was applied")
	}
	if n := f.countRows("mesh_members", ws); n != 0 {
		t.Fatalf("a refused snapshot left %d member rows", n)
	}
	var class string
	if err := f.pool.QueryRow(context.Background(), `SELECT last_error_class FROM mesh_sync_state WHERE workspace_id=$1`, ws).Scan(&class); err != nil || class != "bad_snapshot" {
		t.Fatalf("error class = %q, %v; want bad_snapshot (refused up front, not a store failure)", class, err)
	}
	snap["projects"].([]map[string]any)[0]["name"] = "fine"
	mesh.set(snap)
	mesh.mu.Lock()
	mesh.etagPad = strings.Repeat("e", 200)
	mesh.mu.Unlock()
	if _, err := f.reconcile(ws); err != nil {
		t.Fatalf("a long ETag failed the sync: %v", err)
	}
	if got := f.status("mesh_members", "user_id", ws, bob); got != "active" {
		t.Fatalf("bob = %s after the sync with a long ETag", got)
	}
}

// The fetch must not reach a non-public address over https, whatever mesh_url
// names: a connection to loopback is refused before any request is sent.
func TestMeshFetchRefusesNonPublicHTTPSHosts(t *testing.T) {
	f := newMeshFixture(t, true)
	ws, token := uuid.New(), "tok-"+uuid.NewString()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	var conns atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			_ = c.Close()
		}
	}()
	f.installAt(ws, "https://"+ln.Addr().String(), token)
	if _, err := f.reconcile(ws); err == nil {
		t.Fatal("a loopback https Mesh URL was fetched")
	}
	if n := conns.Load(); n != 0 {
		t.Fatalf("the loopback host accepted %d connection(s): the dial was not refused", n)
	}
	var class string
	if err := f.pool.QueryRow(context.Background(), `SELECT last_error_class FROM mesh_sync_state WHERE workspace_id=$1`, ws).Scan(&class); err != nil || class != "network" {
		t.Fatalf("error class = %q, %v; want network", class, err)
	}
}

func (f *meshFixture) syncState(ws uuid.UUID) string {
	f.t.Helper()
	var s string
	if err := f.pool.QueryRow(context.Background(), `SELECT cursor||'|'||dirty_seq||'|'||synced_seq FROM mesh_sync_state WHERE workspace_id=$1`, ws).Scan(&s); err != nil {
		f.t.Fatal(err)
	}
	return s
}

// A snapshot is a view from the moment its fetch started: a fact Mesh reported
// to Keep as newer must survive it, in both directions (not orphaned because
// the snapshot lacks it, not overwritten because the snapshot disagrees).
func TestMeshSnapshotNeverOverridesNewerEvents(t *testing.T) {
	f := newMeshFixture(t, true)
	ws, token := uuid.New(), "tok-"+uuid.NewString()
	mesh := newFakeMesh(t, ws, token)
	evSecret := f.installAt(ws, mesh.srv.URL, token)
	late, kept, proj, projLate, agent, agentLate, sponsor := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	future := time.Now().Add(2 * time.Minute).UTC()
	ev := func(id, typ string, data map[string]any) {
		t.Helper()
		e := map[string]any{"id": id, "type": typ, "workspace_id": ws.String(), "occurred_at": future.Format(time.RFC3339Nano), "data": data}
		if rec := f.sendEvent(ws, evSecret, e); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", id, rec.Code, answerDiag(rec))
		}
	}
	ev("n-member", "workspace.member.added", map[string]any{"user_id": late})
	ev("n-member-rm", "workspace.member.removed", map[string]any{"user_id": kept})
	ev("n-proj", "project.created", map[string]any{"project_id": projLate, "name": "FromEvent"})
	ev("n-proj2", "project.updated", map[string]any{"project_id": proj, "name": "FromEvent"})
	ev("n-agent", "agent.key.issued", map[string]any{"agent_id": agentLate, "key_id": "kl"})
	ev("n-key", "agent.key.revoked", map[string]any{"agent_id": agent, "key_id": "k1"})
	ev("n-sponsor", "agent.key.issued", map[string]any{"agent_id": agent, "key_id": "k2", "sponsor_user_id": sponsor})

	// Mesh's snapshot lacks late/projLate/agentLate and disagrees about the rest.
	snap := hierarchy(ws, []uuid.UUID{kept}, []uuid.UUID{proj}, map[uuid.UUID][]string{agent: {"k1"}}, "p")
	mesh.set(snap)
	if _, err := f.reconcile(ws); err != nil {
		t.Fatal(err)
	}
	checks := map[string][2]string{
		"late member":         {f.status("mesh_members", "user_id", ws, late), "active"},
		"removed member":      {f.status("mesh_members", "user_id", ws, kept), "removed"},
		"late project":        {f.status("mesh_projects", "project_id", ws, projLate), "active"},
		"late agent":          {f.status("mesh_agents", "agent_id", ws, agentLate), "active"},
		"revoked key":         {f.keyStatus(ws, "k1"), "revoked"},
		"key of a late event": {f.keyStatus(ws, "k2"), "active"},
		"key of a late agent": {f.keyStatus(ws, "kl"), "active"},
	}
	for name, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s = %s, want %s: the snapshot overrode a newer fact", name, c[0], c[1])
		}
	}
	var pname string
	if err := f.pool.QueryRow(context.Background(), `SELECT name FROM mesh_projects WHERE workspace_id=$1 AND project_id=$2`, ws, proj).Scan(&pname); err != nil || pname != "FromEvent" {
		t.Errorf("project name = %q, %v; the snapshot overwrote a newer event", pname, err)
	}
	var sp *uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `SELECT sponsor_user_id FROM mesh_agents WHERE workspace_id=$1 AND agent_id=$2`, ws, agent).Scan(&sp); err != nil || sp == nil || *sp != sponsor {
		t.Errorf("sponsor = %v, %v; the snapshot overwrote a newer event", sp, err)
	}
}

func (f *meshFixture) keyStatus(ws uuid.UUID, key string) string {
	f.t.Helper()
	var s string
	if err := f.pool.QueryRow(context.Background(), `SELECT status FROM mesh_agent_keys WHERE workspace_id=$1 AND key_id=$2`, ws, key).Scan(&s); err != nil {
		return "absent"
	}
	return s
}

// Events of every kind are ordered by their time, not by arrival.
func TestMeshProjectAndAgentEventsAreOrdered(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := uuid.New()
	evSecret := f.installAt(ws, "https://mesh.example.test", "tok-"+uuid.NewString())
	proj, agent, s1, s2 := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	t1, t2 := time.Now().Add(-time.Minute).UTC(), time.Now().UTC()
	send := func(id, typ string, at time.Time, data map[string]any) {
		t.Helper()
		e := map[string]any{"id": id, "type": typ, "workspace_id": ws.String(), "occurred_at": at.Format(time.RFC3339Nano), "data": data}
		if rec := f.sendEvent(ws, evSecret, e); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", id, rec.Code, answerDiag(rec))
		}
	}
	send("o-1", "project.updated", t2, map[string]any{"project_id": proj, "name": "New"})
	send("o-2", "project.created", t1, map[string]any{"project_id": proj, "name": "Old"})
	send("o-3", "agent.key.issued", t2, map[string]any{"agent_id": agent, "key_id": "ka", "sponsor_user_id": s2})
	send("o-4", "agent.key.issued", t1, map[string]any{"agent_id": agent, "key_id": "kb", "sponsor_user_id": s1})
	var name string
	if err := f.pool.QueryRow(context.Background(), `SELECT name FROM mesh_projects WHERE workspace_id=$1`, ws).Scan(&name); err != nil || name != "New" {
		t.Fatalf("project name = %q, %v; an older event overwrote a newer one", name, err)
	}
	var sp uuid.UUID
	if err := f.pool.QueryRow(context.Background(), `SELECT sponsor_user_id FROM mesh_agents WHERE workspace_id=$1`, ws).Scan(&sp); err != nil || sp != s2 {
		t.Fatalf("sponsor = %v, %v; an older event overwrote a newer one", sp, err)
	}
}

// An event that has data but not what its type needs is recorded and forces a
// full fetch, exactly like one without data: a change must never be lost silently.
func TestMeshIncompleteEventsForceFullFetch(t *testing.T) {
	cases := map[string]map[string]any{
		"member without user":  {"type": "workspace.member.added", "data": map[string]any{"role": "admin"}},
		"project without id":   {"type": "project.updated", "data": map[string]any{"name": "x"}},
		"key without key id":   {"type": "agent.key.revoked", "data": map[string]any{"agent_id": uuid.New()}},
		"key without agent id": {"type": "agent.key.issued", "data": map[string]any{"key_id": "k"}},
		"member without time":  {"type": "workspace.member.added", "data": map[string]any{"user_id": uuid.New(), "role": "admin"}},
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			f := newMeshFixture(t, true)
			ws, token := uuid.New(), "tok-"+uuid.NewString()
			mesh := newFakeMesh(t, ws, token)
			evSecret := f.installAt(ws, mesh.srv.URL, token)
			mesh.set(hierarchy(ws, nil, nil, nil, "p"))
			if _, err := f.reconcile(ws); err != nil {
				t.Fatal(err)
			}
			e["id"], e["workspace_id"] = "inc-1", ws.String()
			if name != "member without time" {
				// Timed, so that it is the missing field, not the missing time, that is tested.
				e["occurred_at"] = time.Now().UTC().Format(time.RFC3339)
			}
			if rec := f.sendEvent(ws, evSecret, e); rec.Code != http.StatusOK {
				t.Fatalf("event: %d %s", rec.Code, answerDiag(rec))
			}
			if n := f.countRows("mesh_members", ws); n != 0 {
				t.Fatalf("an event Keep cannot order wrote %d member rows", n)
			}
			if res, err := f.reconcile(ws); err != nil || res.NotModified {
				t.Fatalf("after an incomplete event: %+v, %v; want a full fetch", res, err)
			}
		})
	}
}

// The same key id under two agents is two keys: dropping it from one orphans
// that one only, and a failed fetch never moves the cursor or the sequence.
func TestMeshKeysAreScopedToTheirAgentAndFailuresKeepTheCursor(t *testing.T) {
	f := newMeshFixture(t, true)
	ws, token := uuid.New(), "tok-"+uuid.NewString()
	mesh := newFakeMesh(t, ws, token)
	f.installAt(ws, mesh.srv.URL, token)
	a, b := uuid.New(), uuid.New()
	mesh.set(hierarchy(ws, nil, nil, map[uuid.UUID][]string{a: {"shared"}, b: {"shared"}}, "p"))
	if _, err := f.reconcile(ws); err != nil {
		t.Fatal(err)
	}
	mesh.set(hierarchy(ws, nil, nil, map[uuid.UUID][]string{a: {"shared"}, b: nil}, "p"))
	if res, err := f.reconcile(ws); err != nil || res.Orphaned != 1 {
		t.Fatalf("reconcile = %+v, %v; want exactly b's key orphaned", res, err)
	}
	var sa, sb string
	_ = f.pool.QueryRow(context.Background(), `SELECT status FROM mesh_agent_keys WHERE workspace_id=$1 AND agent_id=$2`, ws, a).Scan(&sa)
	_ = f.pool.QueryRow(context.Background(), `SELECT status FROM mesh_agent_keys WHERE workspace_id=$1 AND agent_id=$2`, ws, b).Scan(&sb)
	if sa != "active" || sb != "orphaned" {
		t.Fatalf("keys = %s / %s, want active / orphaned", sa, sb)
	}
	before := f.syncState(ws)
	mesh.mu.Lock()
	mesh.failWith = 500
	mesh.mu.Unlock()
	if _, err := f.reconcile(ws); err == nil {
		t.Fatal("a failed fetch succeeded")
	}
	mesh.mu.Lock()
	mesh.failWith = 0
	mesh.mu.Unlock()
	mesh.set(hierarchy(uuid.New(), nil, nil, nil, "p")) // another workspace's snapshot: refused
	if _, err := f.reconcile(ws); err == nil {
		t.Fatal("a foreign snapshot was applied")
	}
	if after := f.syncState(ws); after != before {
		t.Fatalf("cursor/sequence moved on a failure: %q -> %q", before, after)
	}
}

// A transport failure names the URL in Go's error text; the token and that text
// must stay out of every surface, like on the HTTP error paths.
func TestMeshNetworkFailureLeaksNothing(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	token := c.Value(1)
	ws := uuid.New()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listens there any more
	f.installAt(ws, "http://"+addr, token)
	_, rerr := f.reconcile(ws)
	if rerr == nil {
		t.Fatal("reconcile of an unreachable Mesh succeeded")
	}
	f.repo.ReconcileAll(context.Background(), f.fetcher, f.logger)
	surfaces := []string{rerr.Error(), fmt.Sprintf("%+v %#v", rerr, rerr), f.logbuf.String()}
	var row string
	if err := f.pool.QueryRow(context.Background(), `SELECT row_to_json(t)::text FROM mesh_sync_state t WHERE workspace_id=$1`, ws).Scan(&row); err != nil {
		t.Fatal(err)
	}
	surfaces = append(surfaces, row)
	if !strings.Contains(row, `"network"`) {
		t.Fatalf("state = %s, want class network", row)
	}
	for i, s := range surfaces {
		if c.In(s) || strings.Contains(s, addr) {
			t.Fatalf("token or Mesh address on surface #%d (%d bytes); the surface is not printed", i, len(s))
		}
	}
}

// Mesh's own delivery: the type and the delivery id travel in X-Mesh-Event and
// X-Mesh-Delivery, the body is flat (workspace_id plus the fields of the
// change) and there is no X-Mesh-Workspace header and no occurred_at. Written
// from the sender (evc-mesh internal/service/workspace_member_service.go,
// project_service.go, agent_key_service.go), not from Keep's parser.
func TestMeshAcceptsMeshsOwnFlatDelivery(t *testing.T) {
	f := newMeshFixture(t, true)
	ws, token := uuid.New(), "tok-"+uuid.NewString()
	mesh := newFakeMesh(t, ws, token)
	evSecret := f.installAt(ws, mesh.srv.URL, token)
	mesh.set(hierarchy(ws, nil, nil, nil, "p"))
	if _, err := f.reconcile(ws); err != nil {
		t.Fatal(err)
	}
	user, proj, agent := uuid.New(), uuid.New(), uuid.New()
	deliver := func(typ, delivery string, body map[string]any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		h := signedHeaders(ws, evSecret, time.Now(), b)
		delete(h, "X-Mesh-Workspace")
		h["X-Mesh-Event"], h["X-Mesh-Delivery"] = typ, delivery
		return f.post("/mesh/events", "", b, h)
	}
	cases := []struct {
		typ  string
		body map[string]any
	}{
		{"workspace.member.added", map[string]any{"workspace_id": ws, "user_id": user, "role": "member"}},
		{"project.created", map[string]any{"workspace_id": ws, "project_id": proj, "slug": "p1", "name": "P1", "is_archived": false}},
		{"agent.key.issued", map[string]any{"workspace_id": ws, "agent_id": agent, "key_id": "key-1", "label": "ci"}},
	}
	for i, c := range cases {
		id := uuid.NewString()
		for range 2 { // the second is a retry: same delivery id
			if rec := deliver(c.typ, id, c.body); rec.Code != http.StatusOK {
				t.Fatalf("%s: %d %s", c.typ, rec.Code, answerDiag(rec))
			}
		}
		if n := f.eventRows(ws); n != i+1 {
			t.Fatalf("after %s and its retry: %d event rows, want %d", c.typ, n, i+1)
		}
	}
	// No time to order by: nothing is written from the event, the next
	// reconciliation reads a full snapshot.
	if res, err := f.reconcile(ws); err != nil || res.NotModified {
		t.Fatalf("after flat events: %+v, %v; want a full fetch", res, err)
	}
	// Without the headers the body names no type and no id.
	b, _ := json.Marshal(map[string]any{"workspace_id": ws, "user_id": user})
	if rec := f.post("/mesh/events", "", b, signedHeaders(ws, evSecret, time.Now(), b)); rec.Code != http.StatusBadRequest {
		t.Fatalf("flat body without X-Mesh-Event: %d, want 400", rec.Code)
	}
}

// Mesh sends workspace.member.removed and a later workspace.member.added of
// the same member with byte-identical bodies; each send has its own
// X-Mesh-Delivery, which its retries repeat (each retry is signed again with a
// new timestamp). Both events are recorded and applied, a retry is a repeat.
func TestMeshFlatRemovedThenAddedSameBodyBothRecorded(t *testing.T) {
	f := newMeshFixture(t, true)
	ws, token := uuid.New(), "tok-"+uuid.NewString()
	mesh := newFakeMesh(t, ws, token)
	evSecret := f.installAt(ws, mesh.srv.URL, token)
	user := uuid.New()
	mesh.set(hierarchy(ws, []uuid.UUID{user}, nil, nil, "p"))
	if _, err := f.reconcile(ws); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"workspace_id": ws, "user_id": user, "role": "member"})
	deliver := func(typ, delivery string, at time.Time) {
		t.Helper()
		h := signedHeaders(ws, evSecret, at, b)
		delete(h, "X-Mesh-Workspace")
		h["X-Mesh-Event"], h["X-Mesh-Delivery"] = typ, delivery
		if rec := f.post("/mesh/events", "", b, h); rec.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", typ, delivery, rec.Code, answerDiag(rec))
		}
	}
	dirty := func() string { return strings.Split(f.syncState(ws), "|")[1] }
	start := dirty()
	removed, added := uuid.NewString(), uuid.NewString()
	deliver("workspace.member.removed", removed, time.Now())
	deliver("workspace.member.added", added, time.Now())
	deliver("workspace.member.added", added, time.Now().Add(time.Second)) // retry: same delivery, new timestamp
	if n := f.eventRows(ws); n != 2 {
		t.Fatalf("removed, added and a retry of added: %d event rows, want 2", n)
	}
	var types []string
	rows, err := f.pool.Query(context.Background(), `SELECT event_type FROM mesh_events WHERE workspace_id=$1 ORDER BY event_type`, ws)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		types = append(types, s)
	}
	rows.Close()
	if strings.Join(types, ",") != "workspace.member.added,workspace.member.removed" {
		t.Fatalf("recorded types %v, want added and removed", types)
	}
	// Applied: each recorded flat event scheduled a full fetch, the retry did not.
	s0, _ := strconv.Atoi(start)
	if s1, _ := strconv.Atoi(dirty()); s1-s0 != 2 {
		t.Fatalf("dirty_seq %s -> %d, want +2", start, s1)
	}
}

// The signature covers "<timestamp>.<body>" and nothing else, so X-Mesh-Event
// and X-Mesh-Delivery are not authenticated. They are read (Mesh's flat form
// has no other carrier of the type and of the send), so whoever replays a
// signed request within the timestamp window can make Keep record a flat
// hierarchy event again by editing them. That is all it can do: a flat event
// only schedules a full fetch, a header cannot turn a hierarchy body into a
// gate no-op, and a gate answer is recognised by its signed fields and
// deduplicated by them alone.
func TestMeshFlatHeadersAreNotTrusted(t *testing.T) {
	f := newMeshFixture(t, true)
	ws, token := uuid.New(), "tok-"+uuid.NewString()
	mesh := newFakeMesh(t, ws, token)
	evSecret := f.installAt(ws, mesh.srv.URL, token)
	mesh.set(hierarchy(ws, nil, nil, nil, "p"))
	if _, err := f.reconcile(ws); err != nil {
		t.Fatal(err)
	}
	user := uuid.New()
	member := map[string]any{"workspace_id": ws, "user_id": user, "role": "member"}
	b, _ := json.Marshal(member)
	signed := signedHeaders(ws, evSecret, time.Now(), b)
	delete(signed, "X-Mesh-Workspace")
	replay := func(body []byte, typ, delivery string) *httptest.ResponseRecorder {
		h := map[string]string{}
		for k, v := range signed {
			h[k] = v
		}
		h["X-Mesh-Event"], h["X-Mesh-Delivery"] = typ, delivery
		return f.post("/mesh/events", "", body, h)
	}
	if rec := replay(b, "workspace.member.removed", "d-1"); rec.Code != http.StatusOK {
		t.Fatalf("original: %d %s", rec.Code, answerDiag(rec))
	}
	if n := f.eventRows(ws); n != 1 {
		t.Fatalf("original recorded %d rows, want 1", n)
	}
	// The same headers again are a retry.
	if rec := replay(b, "workspace.member.removed", "d-1"); rec.Code != http.StatusOK {
		t.Fatalf("retry: %d", rec.Code)
	}
	if n := f.eventRows(ws); n != 1 {
		t.Fatalf("a retry was recorded again: %d event rows, want 1", n)
	}
	// Edited headers make a new flat event, which changes no mirrored row.
	before := f.status("mesh_members", "user_id", ws, user)
	if rec := replay(b, "workspace.member.added", "d-2"); rec.Code != http.StatusOK {
		t.Fatalf("replay with edited headers: %d", rec.Code)
	}
	if got := f.status("mesh_members", "user_id", ws, user); got != before {
		t.Fatalf("a replayed flat event changed the member: %q -> %q", before, got)
	}
	// A stated time in a flat body does not make it apply: a replay relabelled
	// from added to removed, or from issued to revoked, changes no row.
	agent := uuid.New()
	keysBefore := f.countRows("mesh_agent_keys", ws)
	for _, c := range []struct {
		body             map[string]any
		orig, relabelled string
		table, idCol     string
		id               uuid.UUID
	}{
		{map[string]any{"workspace_id": ws, "user_id": user, "role": "member"},
			"workspace.member.added", "workspace.member.removed", "mesh_members", "user_id", user},
		{map[string]any{"workspace_id": ws, "agent_id": agent, "key_id": "key-1", "label": "ci"},
			"agent.key.issued", "agent.key.revoked", "mesh_agents", "agent_id", agent},
	} {
		c.body["occurred_at"] = time.Now().UTC().Format(time.RFC3339Nano)
		tb, _ := json.Marshal(c.body)
		th := signedHeaders(ws, evSecret, time.Now(), tb)
		delete(th, "X-Mesh-Workspace")
		before := f.status(c.table, c.idCol, ws, c.id)
		for i, typ := range []string{c.orig, c.relabelled} {
			th["X-Mesh-Event"], th["X-Mesh-Delivery"] = typ, fmt.Sprintf("t-%s-%d", c.orig, i)
			if rec := f.post("/mesh/events", "", tb, th); rec.Code != http.StatusOK {
				t.Fatalf("timed flat %s: %d %s", typ, rec.Code, answerDiag(rec))
			}
			if got := f.status(c.table, c.idCol, ws, c.id); got != before {
				t.Fatalf("timed flat %s applied: %q -> %q", typ, before, got)
			}
		}
	}
	if n := f.countRows("mesh_agent_keys", ws); n != keysBefore {
		t.Fatalf("timed flat key events wrote %d key rows, want %d", n, keysBefore)
	}
	rowsNow := f.eventRows(ws)
	// A hierarchy body relabelled as a gate answer is refused, not dropped as a no-op.
	if rec := replay(b, "task.gate.decided", "d-3"); rec.Code != http.StatusBadRequest {
		t.Fatalf("hierarchy body with a gate type header: %d, want 400", rec.Code)
	}
	if n := f.eventRows(ws); n != rowsNow {
		t.Fatalf("relabelled event was recorded: %d rows, want %d", n, rowsNow)
	}
	// A gate answer is a gate answer whatever the header says.
	gate, _ := json.Marshal(map[string]any{"workspace_id": ws, "task_id": uuid.NewString(), "decision": "approve",
		"decided_by": uuid.NewString(), "decided_by_type": "user", "external_hash": "h"})
	signed = signedHeaders(ws, evSecret, time.Now(), gate)
	delete(signed, "X-Mesh-Workspace")
	if rec := replay(gate, "project.created", "d-4"); rec.Code != http.StatusOK {
		t.Fatalf("gate answer under a hierarchy header: %d %s", rec.Code, answerDiag(rec))
	}
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM mesh_events WHERE workspace_id=$1 AND event_type='task.gate.decided'`, ws).Scan(&n); err != nil || n != 1 {
		t.Fatalf("gate answers recorded as task.gate.decided: %d (%v), want 1", n, err)
	}
}

// PostgreSQL keeps microseconds: two facts less than a microsecond apart are
// the same instant to the row, so the outcome must not depend on which one is
// delivered first.
func TestMeshSubMicrosecondFactsAreOrderIndependent(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		f := newMeshFixture(t, true)
		ws := uuid.New()
		evSecret := f.installAt(ws, "https://mesh.example.test", "tok-"+uuid.NewString())
		user, agent := uuid.New(), uuid.New()
		t0 := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
		ev := func(id, typ string, at time.Time, data map[string]any) map[string]any {
			return map[string]any{"id": id, "type": typ, "workspace_id": ws.String(), "occurred_at": at.Format(time.RFC3339Nano), "data": data}
		}
		pairs := [][2]map[string]any{
			{ev("m-a", "workspace.member.added", t0, map[string]any{"user_id": user}),
				ev("m-r", "workspace.member.removed", t0.Add(100*time.Nanosecond), map[string]any{"user_id": user})},
			{ev("k-a", "agent.key.issued", t0, map[string]any{"agent_id": agent, "key_id": "k1"}),
				ev("k-r", "agent.key.revoked", t0.Add(100*time.Nanosecond), map[string]any{"agent_id": agent, "key_id": "k1"})},
		}
		for _, p := range pairs {
			if reverse {
				p[0], p[1] = p[1], p[0]
			}
			for _, e := range p {
				if rec := f.sendEvent(ws, evSecret, e); rec.Code != http.StatusOK {
					t.Fatalf("%v: %d %s", e["id"], rec.Code, answerDiag(rec))
				}
			}
		}
		if got := f.status("mesh_members", "user_id", ws, user); got != "removed" {
			t.Fatalf("reverse=%v: member = %s, want removed", reverse, got)
		}
		if got := f.keyStatus(ws, "k1"); got != "revoked" {
			t.Fatalf("reverse=%v: key = %s, want revoked", reverse, got)
		}
	}
}

// Partial project.updated events of the same microsecond each carry one field;
// the row must be the same whichever is delivered first.
func TestMeshPartialProjectTieConverges(t *testing.T) {
	var rows [2]string
	for i, reverse := range []bool{false, true} {
		f := newMeshFixture(t, true)
		ws := uuid.New()
		evSecret := f.installAt(ws, "https://mesh.example.test", "tok-"+uuid.NewString())
		proj := uuid.New()
		t0 := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
		ev := func(id string, at time.Time, data map[string]any) map[string]any {
			data["project_id"] = proj
			return map[string]any{"id": id, "type": "project.updated", "workspace_id": ws.String(), "occurred_at": at.Format(time.RFC3339Nano), "data": data}
		}
		pair := [2]map[string]any{
			ev("p-name", t0, map[string]any{"name": "Zed"}),
			ev("p-slug", t0.Add(100*time.Nanosecond), map[string]any{"slug": "new-slug"}),
		}
		if reverse {
			pair[0], pair[1] = pair[1], pair[0]
		}
		for _, e := range pair {
			if rec := f.sendEvent(ws, evSecret, e); rec.Code != http.StatusOK {
				t.Fatalf("%v: %d %s", e["id"], rec.Code, answerDiag(rec))
			}
		}
		var name, slug string
		if err := f.pool.QueryRow(context.Background(), `SELECT name, slug FROM mesh_projects WHERE workspace_id=$1 AND project_id=$2`, ws, proj).Scan(&name, &slug); err != nil {
			t.Fatal(err)
		}
		rows[i] = name + "/" + slug
	}
	if rows[0] != rows[1] || rows[0] != "Zed/new-slug" {
		t.Fatalf("forward=%q reverse=%q, want both Zed/new-slug", rows[0], rows[1])
	}
}

// A project that already exists, then partial updates carrying different
// fields, several in the same microsecond: in every delivery order each field
// ends at its newest stated value (true -> false included), ties going to the
// larger value.
func TestMeshSeededPartialProjectConverges(t *testing.T) {
	type step struct {
		dt   time.Duration
		data map[string]any
	}
	cases := map[string]struct {
		steps []step
		want  string
	}{
		"newer-name-and-archive-after-slug": {
			[]step{
				{0, map[string]any{"slug": "new-slug"}},
				{100 * time.Nanosecond, map[string]any{"name": "Alpha", "is_archived": false}},
			},
			"Alpha/new-slug/false",
		},
		"stale-values-and-ties": {
			[]step{
				{0, map[string]any{"slug": "s1", "name": "N1", "is_archived": true}},
				{time.Microsecond, map[string]any{"slug": "s2"}},
				{2 * time.Microsecond, map[string]any{"is_archived": false}},
				{3 * time.Microsecond, map[string]any{"name": "N2", "is_archived": true}},
				{3 * time.Microsecond, map[string]any{"name": "N3", "is_archived": false}},
				{3 * time.Microsecond, map[string]any{"slug": "s3"}},
				{3 * time.Microsecond, map[string]any{"slug": "s0"}},
			},
			"N3/s3/true",
		},
		"absent-field-is-not-a-fact": {
			[]step{
				{0, map[string]any{"slug": "s1"}},
				{time.Microsecond, map[string]any{"name": "N1"}},
			},
			"N1/s1/true",
		},
	}
	f := newMeshFixture(t, true)
	ws := uuid.New()
	evSecret := f.installAt(ws, "https://mesh.example.test", "tok-"+uuid.NewString())
	t0 := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
	for name, c := range cases {
		idx := make([]int, len(c.steps))
		for i := range idx {
			idx[i] = i
		}
		var run func(k int)
		run = func(k int) {
			if k == len(idx) {
				proj := uuid.New()
				send := func(id, typ string, at time.Time, data map[string]any) {
					d := map[string]any{"project_id": proj}
					for key, v := range data {
						d[key] = v
					}
					e := map[string]any{"id": id, "type": typ, "workspace_id": ws.String(), "occurred_at": at.Format(time.RFC3339Nano), "data": d}
					if rec := f.sendEvent(ws, evSecret, e); rec.Code != http.StatusOK {
						t.Fatalf("%s: %d %s", id, rec.Code, answerDiag(rec))
					}
				}
				send("seed-"+proj.String(), "project.created", t0.Add(-time.Hour), map[string]any{"slug": "old-slug", "name": "Zed", "is_archived": true})
				for _, i := range idx {
					send(fmt.Sprintf("e%d-%s", i, proj), "project.updated", t0.Add(c.steps[i].dt), c.steps[i].data)
				}
				var n, sl string
				var arch bool
				if err := f.pool.QueryRow(context.Background(), `SELECT name, slug, is_archived FROM mesh_projects WHERE workspace_id=$1 AND project_id=$2`, ws, proj).Scan(&n, &sl, &arch); err != nil {
					t.Fatal(err)
				}
				if got := fmt.Sprintf("%s/%s/%v", n, sl, arch); got != c.want {
					t.Fatalf("%s: delivery order %v gave %q, want %q", name, idx, got, c.want)
				}
				return
			}
			for i := k; i < len(idx); i++ {
				idx[k], idx[i] = idx[i], idx[k]
				run(k + 1)
				idx[k], idx[i] = idx[i], idx[k]
			}
		}
		run(0)
	}
}

// An event older than the moment a project was orphaned does not bring it back.
func TestMeshStaleEventDoesNotReviveOrphanedProject(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := uuid.New()
	evSecret := f.installAt(ws, "https://mesh.example.test", "tok-"+uuid.NewString())
	proj := uuid.New()
	t0 := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	send := func(id string, at time.Time) {
		e := map[string]any{"id": id, "type": "project.updated", "workspace_id": ws.String(), "occurred_at": at.Format(time.RFC3339Nano), "data": map[string]any{"project_id": proj, "name": "P"}}
		if rec := f.sendEvent(ws, evSecret, e); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", id, rec.Code, answerDiag(rec))
		}
	}
	status := func() string {
		var st string
		if err := f.pool.QueryRow(context.Background(), `SELECT status FROM mesh_projects WHERE workspace_id=$1 AND project_id=$2`, ws, proj).Scan(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	send("first", t0)
	if _, err := f.pool.Exec(context.Background(), `UPDATE mesh_projects SET status='orphaned', orphaned_at=$3, state_at=$3 WHERE workspace_id=$1 AND project_id=$2`, ws, proj, t0.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	send("stale", t0.Add(time.Minute))
	if got := status(); got != "orphaned" {
		t.Fatalf("a stale event revived the project: %s", got)
	}
	send("fresh", t0.Add(20*time.Minute))
	if got := status(); got != "active" {
		t.Fatalf("a newer event did not restore the project: %s", got)
	}
}

// Member, agent and key events carry optional fields (role, sponsor, label).
// An event that omits one states nothing about it, so in every delivery order
// the row ends with the newest stated value and the newest status, with or
// without a timestamp tie.
func TestMeshPartialMemberAgentKeyConverges(t *testing.T) {
	sponsor := uuid.New()
	type step struct {
		dt   time.Duration
		typ  string
		data map[string]any
	}
	cases := []struct {
		name, kind, want string
		steps            []step
	}{
		{"agent-sponsor-then-bare", "agent", sponsor.String() + "/active", []step{
			{0, "agent.key.issued", map[string]any{"sponsor_user_id": sponsor}},
			{time.Second, "agent.key.issued", map[string]any{}},
		}},
		{"member-role-then-bare-removal", "member", "admin/removed", []step{
			{0, "workspace.member.added", map[string]any{"role": "admin"}},
			{time.Second, "workspace.member.removed", map[string]any{}},
		}},
		{"member-role-tie-with-bare-removal", "member", "admin/removed", []step{
			{0, "workspace.member.added", map[string]any{"role": "admin"}},
			{0, "workspace.member.removed", map[string]any{}},
		}},
		{"key-label-then-bare-revoke", "key", "Laptop/revoked", []step{
			{0, "agent.key.issued", map[string]any{"label": "Laptop"}},
			{time.Second, "agent.key.revoked", map[string]any{}},
		}},
		{"key-label-newer-wins", "key", "New/revoked", []step{
			{0, "agent.key.issued", map[string]any{"label": "Old"}},
			{time.Second, "agent.key.issued", map[string]any{"label": "New"}},
			{2 * time.Second, "agent.key.revoked", map[string]any{}},
		}},
	}
	f := newMeshFixture(t, true)
	ws := uuid.New()
	evSecret := f.installAt(ws, "https://mesh.example.test", "tok-"+uuid.NewString())
	t0 := time.Now().Add(-time.Minute).UTC().Truncate(time.Microsecond)
	for _, c := range cases {
		idx := make([]int, len(c.steps))
		for i := range idx {
			idx[i] = i
		}
		var run func(k int)
		run = func(k int) {
			if k < len(idx) {
				for i := k; i < len(idx); i++ {
					idx[k], idx[i] = idx[i], idx[k]
					run(k + 1)
					idx[k], idx[i] = idx[i], idx[k]
				}
				return
			}
			user, agent := uuid.New(), uuid.New()
			for _, i := range idx {
				s := c.steps[i]
				d := map[string]any{"user_id": user, "agent_id": agent, "key_id": "key-1"}
				for key, v := range s.data {
					d[key] = v
				}
				e := map[string]any{"id": fmt.Sprintf("%s-%d-%s", c.name, i, agent), "type": s.typ, "workspace_id": ws.String(), "occurred_at": t0.Add(s.dt).Format(time.RFC3339Nano), "data": d}
				if rec := f.sendEvent(ws, evSecret, e); rec.Code != http.StatusOK {
					t.Fatalf("%s: %d %s", c.name, rec.Code, answerDiag(rec))
				}
			}
			var got string
			var err error
			switch c.kind {
			case "agent":
				err = f.pool.QueryRow(context.Background(), `SELECT COALESCE(sponsor_user_id::text,'NULL')||'/'||status FROM mesh_agents WHERE workspace_id=$1 AND agent_id=$2`, ws, agent).Scan(&got)
			case "member":
				err = f.pool.QueryRow(context.Background(), `SELECT role||'/'||status FROM mesh_members WHERE workspace_id=$1 AND user_id=$2`, ws, user).Scan(&got)
			default:
				err = f.pool.QueryRow(context.Background(), `SELECT label||'/'||status FROM mesh_agent_keys WHERE workspace_id=$1 AND agent_id=$2 AND key_id='key-1'`, ws, agent).Scan(&got)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("%s: delivery order %v gave %q, want %q", c.name, idx, got, c.want)
			}
		}
		run(0)
	}
}

// An event older than the moment an entity was orphaned does not bring a
// member, an agent or a key back.
func TestMeshStaleEventDoesNotReviveOrphanedEntities(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := uuid.New()
	evSecret := f.installAt(ws, "https://mesh.example.test", "tok-"+uuid.NewString())
	user, agent := uuid.New(), uuid.New()
	t0 := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	send := func(id, typ string, at time.Time) {
		d := map[string]any{"user_id": user, "agent_id": agent, "key_id": "key-1", "role": "admin", "label": "L"}
		e := map[string]any{"id": id, "type": typ, "workspace_id": ws.String(), "occurred_at": at.Format(time.RFC3339Nano), "data": d}
		if rec := f.sendEvent(ws, evSecret, e); rec.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", id, rec.Code, answerDiag(rec))
		}
	}
	send("m1", "workspace.member.added", t0)
	send("k1", "agent.key.issued", t0)
	orphanAt := t0.Add(10 * time.Minute)
	for _, q := range []string{
		`UPDATE mesh_members SET status='orphaned', orphaned_at=$2, state_at=$2 WHERE workspace_id=$1`,
		`UPDATE mesh_agents SET status='orphaned', orphaned_at=$2, state_at=$2 WHERE workspace_id=$1`,
		`UPDATE mesh_agent_keys SET status='orphaned', orphaned_at=$2, state_at=$2 WHERE workspace_id=$1`,
	} {
		if _, err := f.pool.Exec(context.Background(), q, ws, orphanAt); err != nil {
			t.Fatal(err)
		}
	}
	send("m-stale", "workspace.member.added", t0.Add(time.Minute))
	send("k-stale", "agent.key.issued", t0.Add(time.Minute))
	for _, tbl := range []string{"mesh_members", "mesh_agents", "mesh_agent_keys"} {
		var st string
		if err := f.pool.QueryRow(context.Background(), `SELECT status FROM `+tbl+` WHERE workspace_id=$1`, ws).Scan(&st); err != nil {
			t.Fatal(err)
		}
		if st != "orphaned" {
			t.Fatalf("%s: a stale event revived the row: status %q", tbl, st)
		}
	}
}
