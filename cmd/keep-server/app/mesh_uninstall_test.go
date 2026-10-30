package app

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/api"
	"github.com/entire-vc/evc-keep/internal/apperr"
	"github.com/entire-vc/evc-keep/internal/builtin"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (f *meshFixture) uninstallPath(org, ws uuid.UUID) string {
	return "/orgs/" + org.String() + "/mesh/installations/" + ws.String()
}

// uninstall sends DELETE /orgs/{org}/mesh/installations/{ws}; viaTLS false
// is the plain listener.
func (f *meshFixture) uninstallAt(path, bearer string, viaTLS bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodDelete, path, nil)
	if viaTLS {
		r.TLS = &tls.ConnectionState{}
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, r)
	return rec
}

func (f *meshFixture) uninstall(bearer string, ws uuid.UUID) *httptest.ResponseRecorder {
	return f.uninstallAt(f.uninstallPath(f.org.ID, ws), bearer, true)
}

// meshUninstallWire is the closed answer of a removal (threat model §4.3).
type meshUninstallWire struct {
	WorkspaceID string `json:"workspace_id"`
	Erased      int    `json:"erased"`
	RequestID   string `json:"request_id"`
}

func decodeUninstall(t *testing.T, rec *httptest.ResponseRecorder) meshUninstallWire {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("uninstall status = %d, %s", rec.Code, answerDiag(rec))
	}
	dec := json.NewDecoder(strings.NewReader(rec.Body.String()))
	dec.DisallowUnknownFields()
	var w meshUninstallWire
	if err := dec.Decode(&w); err != nil {
		t.Fatalf("uninstall answer is not the closed shape: %s", answerDiag(rec))
	}
	return w
}

// liveEnvelopes counts the versions under mesh/<ws>/ that can still be
// opened: not erased, or still holding a wrapped DEK.
func (f *meshFixture) liveEnvelopes(org, ws uuid.UUID) int {
	return f.count(`SELECT count(*) FROM keep_envelope WHERE store_org = $1 AND left(secret_id, $2) = $3
		AND (status <> 'erased' OR wrapped_dek IS NOT NULL OR kek_id IS NOT NULL)`,
		org.String(), len("mesh/"+ws.String()+"/"), "mesh/"+ws.String()+"/")
}

// meshRows counts the rows a workspace has in every table keyed by it.
func (f *meshFixture) meshRows(ws uuid.UUID) map[string]int {
	out := map[string]int{}
	for _, table := range []string{"mesh_installations", "mesh_events", "mesh_sync_state", "mesh_secret_nonces",
		"mesh_members", "mesh_projects", "mesh_agents", "mesh_agent_keys", "mesh_user_links", "mesh_gate_requests",
		"mesh_pending_installs"} {
		out[table] = f.count(`SELECT count(*) FROM `+table+` WHERE workspace_id = $1`, ws)
	}
	return out
}

// Leak test (written before the feature): the credentials Mesh handed over at
// install and a value the workspace stored are on no surface of a removal —
// its answer and headers, the refusals, the log, the audit journal — and the
// answer carries neither a fingerprint nor a version of them.
func TestMeshUninstallNeverLeaks(t *testing.T) {
	f := newMeshFixture(t, true)
	c := canary.New()
	if !c.In("x"+c.Value(1)) || !c.In(strings.ToUpper(c.Value(2))) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	token, evSecret, value := c.Value(1), c.Value(2)+"-events", c.Value(3)
	ws := uuid.New()
	keepSecret := installedKeepSecret(t, f.install(f.admin, ws, token, evSecret))
	put := f.secretsDo(secretCall{method: http.MethodPut, path: f.secretPath(f.org.ID, "db-password", false),
		body: []byte(`{"value":"` + value + `"}`), ws: ws, secret: evSecret})
	wantStatus(t, put, http.StatusOK, "put before uninstall")
	var putMeta struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(put.Body.Bytes(), &putMeta); err != nil || putMeta.Fingerprint == "" {
		t.Fatalf("put answer: %s", answerDiag(put))
	}

	var answers []*httptest.ResponseRecorder
	answers = append(answers,
		f.uninstall(f.member, ws),                                    // not an admin
		f.uninstallAt(f.uninstallPath(f.org.ID, ws), f.admin, false), // plain listener
		f.uninstall(f.admin, uuid.New()),                             // not installed
	)
	ok := f.uninstall(f.admin, ws)
	decodeUninstall(t, ok)
	answers = append(answers, ok, f.uninstall(f.admin, ws)) // and its repeat

	surfaces := f.surfaces()
	for _, rec := range answers {
		surfaces = append(surfaces, rec.Body.String(), headersText(rec))
	}
	if f.logbuf.Len() == 0 {
		t.Fatal("logger captured nothing; the log check proves nothing")
	}
	for name, cc := range map[string]canary.Canary{
		"extension token": c, "events secret": canary.Of(evSecret), "stored value": canary.Of(value), "keep secret": canary.Of(keepSecret),
	} {
		for i, s := range surfaces {
			if cc.In(s) {
				t.Fatalf("%s leaked on surface #%d (%d bytes); the surface is not printed", name, i, len(s))
			}
		}
	}
	// No fingerprint either: not in the answers, the log or the removal's
	// journal records (the put's own record legitimately holds one).
	var journal string
	if err := f.pool.QueryRow(context.Background(), `SELECT coalesce(string_agg(row_to_json(a)::text, E'\n'), '') FROM audit_records a
		WHERE action = 'mesh.uninstall'`).Scan(&journal); err != nil || journal == "" {
		t.Fatalf("no mesh.uninstall journal records to check: %v", err)
	}
	removal := []string{f.logbuf.String(), journal}
	for _, rec := range answers {
		removal = append(removal, rec.Body.String(), headersText(rec))
	}
	for i, s := range removal {
		if strings.Contains(s, "kfp1:") || strings.Contains(s, putMeta.Fingerprint) {
			t.Fatalf("removal surface #%d carries a fingerprint", i)
		}
	}
}

// After a removal nothing of the workspace is left: no installation, no
// mirrored metadata, no envelope that opens. A second workspace of the same
// organisation is untouched and keeps working.
func TestMeshUninstallErasesAndCascades(t *testing.T) {
	f := newMeshFixture(t, true)
	ctx := context.Background()
	ws, other := f.installedWorkspace(), f.installedWorkspace()
	for _, w := range []uuid.UUID{ws, other} {
		wantStatus(t, f.putSecret(w, "db-password", "v-1"), http.StatusOK, "put")
		wantStatus(t, f.putSecret(w, "db-password", "v-2"), http.StatusOK, "put again")
		wantStatus(t, f.putSecret(w, "api-key", "v-3"), http.StatusOK, "put other ref")
		body := eventBody(w, "evt-"+w.String()[:8], "project.created")
		wantStatus(t, f.post("/mesh/events", "", body, signedHeaders(w, meshTestEventsSecret, time.Now(), body)), http.StatusOK, "event")
		if _, err := f.pool.Exec(ctx, `INSERT INTO mesh_sync_state (workspace_id, cursor) VALUES ($1, 'c1') ON CONFLICT (workspace_id) DO NOTHING`, w); err != nil {
			t.Fatalf("seed sync state: %v", err)
		}
		if _, err := f.pool.Exec(ctx, `INSERT INTO mesh_projects (workspace_id, project_id, status, state_at) VALUES ($1, gen_random_uuid(), 'active', now())`, w); err != nil {
			t.Fatalf("seed project: %v", err)
		}
	}
	// A disabled version is erased like any other, and an open install window
	// is closed (the neighbour's stays).
	if _, err := f.pool.Exec(ctx, `UPDATE keep_envelope SET status = 'disabled' WHERE ctid = (SELECT ctid FROM keep_envelope
		WHERE store_org = $1 AND left(secret_id, $2) = $3 AND status = 'active' ORDER BY secret_id, version LIMIT 1)`,
		f.org.ID.String(), len("mesh/"+ws.String()+"/"), "mesh/"+ws.String()+"/"); err != nil {
		t.Fatalf("disable a version: %v", err)
	}
	for _, w := range []uuid.UUID{ws, other} {
		if _, err := f.pool.Exec(ctx, `INSERT INTO mesh_pending_installs (workspace_id, org_id, opened_by, mesh_url, secret_sha256, expires_at)
			VALUES ($1, $2, gen_random_uuid(), 'https://mesh.example.test', $3, now() + interval '10 minutes')`,
			w, f.org.ID, meshSecretSHA256("window-"+w.String())); err != nil {
			t.Fatalf("seed install window: %v", err)
		}
	}
	before := f.liveEnvelopes(f.org.ID, ws)
	// Three credentials of the install and three secret versions, one disabled.
	if before != 6 {
		t.Fatalf("live envelopes before removal = %d, want 6", before)
	}
	otherBefore, otherRows := f.liveEnvelopes(f.org.ID, other), f.meshRows(other)

	got := decodeUninstall(t, f.uninstall(f.admin, ws))
	if got.WorkspaceID != ws.String() || got.Erased != before || got.RequestID == "" {
		t.Fatalf("answer = %+v, want workspace %s erased %d and a request id", got, ws, before)
	}
	if n := f.liveEnvelopes(f.org.ID, ws); n != 0 {
		t.Fatalf("%d envelopes of the removed workspace still open", n)
	}
	for table, n := range f.meshRows(ws) {
		if n != 0 {
			t.Errorf("%s keeps %d rows of the removed workspace", table, n)
		}
	}
	if n := f.liveEnvelopes(f.org.ID, other); n != otherBefore {
		t.Errorf("neighbour envelopes = %d, want %d", n, otherBefore)
	}
	for table, n := range f.meshRows(other) {
		if n != otherRows[table] {
			t.Errorf("neighbour %s rows = %d, want %d", table, n, otherRows[table])
		}
	}
	wantStatus(t, f.resolveSecret(other, "db-password"), http.StatusOK, "neighbour resolve")
	// The removed workspace authenticates nothing any more.
	if rec := f.resolveSecret(ws, "db-password"); rec.Code == http.StatusOK {
		t.Fatal("removed workspace still resolves its secret")
	}
	body := eventBody(ws, "after-removal", "project.created")
	if rec := f.post("/mesh/events", "", body, signedHeaders(ws, meshTestEventsSecret, time.Now(), body)); rec.Code == http.StatusOK {
		t.Fatal("removed workspace still delivers events")
	}

	// A repeat finds nothing: the same answer as a workspace never installed.
	again, never := f.uninstall(f.admin, ws), f.uninstall(f.admin, uuid.New())
	wantStatus(t, again, http.StatusNotFound, "repeat")
	wantStatus(t, never, http.StatusNotFound, "never installed")
	if stripRequestID(again.Body.String()) != stripRequestID(never.Body.String()) {
		t.Error("a removed workspace answers differently from one never installed")
	}

	var reason string
	if err := f.pool.QueryRow(ctx, `SELECT intent_reason FROM audit_records WHERE org_id = $1 AND action = 'mesh.uninstall' AND result_status = 'ok'`,
		f.org.ID.String()).Scan(&reason); err != nil {
		t.Fatalf("no ok mesh.uninstall record: %v", err)
	}
	if want := "workspace=" + ws.String() + " erased=6"; reason != want {
		t.Errorf("audit reason = %q, want %q", reason, want)
	}

	// The workspace can be connected again from scratch.
	installedKeepSecret(t, f.install(f.admin, ws, "tok-2", meshTestEventsSecret))
	if rec := f.resolveSecret(ws, "db-password"); rec.Code != http.StatusNotFound {
		t.Fatalf("reinstalled workspace resolves an erased secret: %d", rec.Code)
	}
}

// Only an admin of the organisation removes, only its own workspace, only
// over TLS; another organisation's workspace is not distinguishable from
// one that does not exist.
func TestMeshUninstallAuthorization(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()

	tr := tenancy.New(f.pool)
	otherOrg, err := tr.CreateOrganization(context.Background(), t.Name()+"-other", "")
	if err != nil {
		t.Fatal(err)
	}
	g := &meshFixture{t: t, pool: f.pool, router: f.router, org: otherOrg}
	g.admin = g.bearer(tr, "admin2", true)
	foreign := uuid.New()
	installedKeepSecret(t, g.install(g.admin, foreign, "tok-g", meshTestEventsSecret))

	wantStatus(t, f.uninstall("", ws), http.StatusUnauthorized, "no bearer")
	member := f.uninstall(f.member, ws)
	wantStatus(t, member, http.StatusForbidden, "member")
	if !strings.Contains(member.Body.String(), `"error_class":"`+string(apperr.ClassPermissionDenied)+`"`) {
		t.Errorf("member refusal: %s", answerDiag(member))
	}
	wantStatus(t, f.uninstall(f.pollerBearer(), ws), http.StatusForbidden, "poller service")
	wantStatus(t, f.uninstallAt(f.uninstallPath(f.org.ID, ws), f.admin, false), http.StatusNotFound, "plain listener")

	never := f.uninstall(f.admin, uuid.New())
	wantStatus(t, never, http.StatusNotFound, "never installed")
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"foreign workspace under own org": f.uninstall(f.admin, foreign),
		"foreign org in the path":         f.uninstallAt(f.uninstallPath(otherOrg.ID, foreign), f.admin, true),
		"own workspace under foreign org": f.uninstallAt(f.uninstallPath(otherOrg.ID, ws), f.admin, true),
	} {
		wantStatus(t, rec, http.StatusNotFound, name)
		if stripRequestID(rec.Body.String()) != stripRequestID(never.Body.String()) {
			t.Errorf("%s: answer differs from a workspace never installed", name)
		}
	}
	if rec := f.uninstallAt("/orgs/"+f.org.ID.String()+"/mesh/installations/not-a-uuid", f.admin, true); rec.Code != http.StatusNotFound {
		t.Errorf("malformed workspace: status = %d, want 404", rec.Code)
	}

	// Nothing of either workspace moved.
	if f.meshRows(ws)["mesh_installations"] != 1 || f.meshRows(foreign)["mesh_installations"] != 1 {
		t.Fatal("a refused removal deleted an installation")
	}
	if f.liveEnvelopes(f.org.ID, ws) != 3 || f.liveEnvelopes(otherOrg.ID, foreign) != 3 {
		t.Fatal("a refused removal erased credentials")
	}
	denied := f.count(`SELECT count(*) FROM audit_records WHERE org_id = $1 AND action = 'mesh.uninstall' AND result_status = 'failed' AND result_error_class = 'permission_denied'`, f.org.ID.String())
	if denied != 1 {
		t.Errorf("denied mesh.uninstall records = %d, want 1 (the member)", denied)
	}
	// The foreign organisation's admin removes its own workspace.
	decodeUninstall(t, g.uninstallAt(g.uninstallPath(otherOrg.ID, foreign), g.admin, true))
}

// eraseToggleVault, while fail is set, erases for real and then reports a
// failure, so the test sees whether the erasure is rolled back with the rest.
type eraseToggleVault struct {
	api.MeshVault
	fail *atomic.Bool
}

func (v eraseToggleVault) EraseWorkspace(ctx context.Context, tx pgx.Tx, org, workspace string) (int, error) {
	n, err := v.MeshVault.EraseWorkspace(ctx, tx, org, workspace)
	if err == nil && v.fail.Load() {
		return n, errors.New("erase switched off")
	}
	return n, err
}

// A failed erasure keeps the installation: the answer is a 5xx with a class,
// nothing is deleted, and the repeat completes the removal.
func TestMeshUninstallEraseFailureKeepsInstallation(t *testing.T) {
	var fail atomic.Bool
	f := newMeshFixtureOn(t, testPool(t), true, func(d *api.MeshDeps) { d.Vault = eraseToggleVault{MeshVault: d.Vault, fail: &fail} })
	ws := f.installedWorkspace()
	wantStatus(t, f.putSecret(ws, "db-password", "v-1"), http.StatusOK, "put")

	fail.Store(true)
	rec := f.uninstall(f.admin, ws)
	if rec.Code < 500 || !strings.Contains(rec.Body.String(), `"error_class":"`+string(apperr.ClassInternal)+`"`) {
		t.Fatalf("failed erasure: status = %d, %s", rec.Code, answerDiag(rec))
	}
	if n := f.meshRows(ws)["mesh_installations"]; n != 1 {
		t.Fatal("a failed erasure deleted the installation")
	}
	if n := f.liveEnvelopes(f.org.ID, ws); n != 4 {
		t.Fatalf("live versions after a failed removal = %d, want 4: the erasure was not rolled back", n)
	}
	wantStatus(t, f.resolveSecret(ws, "db-password"), http.StatusOK, "resolve after failed removal")
	if n := f.count(`SELECT count(*) FROM audit_records WHERE org_id = $1 AND action = 'mesh.uninstall' AND result_status = 'failed' AND result_error_class = 'internal'`, f.org.ID.String()); n != 1 {
		t.Errorf("failed mesh.uninstall records = %d, want 1", n)
	}

	fail.Store(false)
	got := decodeUninstall(t, f.uninstall(f.admin, ws))
	if got.Erased != 4 || f.liveEnvelopes(f.org.ID, ws) != 0 || f.meshRows(ws)["mesh_installations"] != 0 {
		t.Fatalf("repeat after a failed erasure: erased %d, live %d", got.Erased, f.liveEnvelopes(f.org.ID, ws))
	}
}

// A removal and a secrets write of one workspace take the same lock: the
// removal waits for a write in flight, and a write that waited for a removal
// finds no installation and stores nothing, so no value outlives the erasure.
func TestMeshUninstallSerializesWithSecretWrites(t *testing.T) {
	f := newMeshFixture(t, true)
	ctx := context.Background()
	ws := f.installedWorkspace()
	rawUnlock, err := f.repo.LockWorkspace(ctx, ws)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	unlock := func() { once.Do(rawUnlock) }
	defer unlock()

	removed := make(chan *httptest.ResponseRecorder, 1)
	go func() { removed <- f.uninstall(f.admin, ws) }()
	select {
	case <-removed:
		t.Fatal("removal completed while the workspace lock was held")
	case <-time.After(500 * time.Millisecond):
	}
	written := make(chan *httptest.ResponseRecorder, 1)
	go func() { written <- f.putSecret(ws, "db-password", "late") }()
	select {
	case <-written:
		t.Fatal("secret write completed while the workspace lock was held")
	case <-time.After(500 * time.Millisecond):
	}
	unlock()
	for _, ch := range []chan *httptest.ResponseRecorder{removed, written} {
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Fatal("a call did not proceed after the lock was released")
		}
	}
	if n := f.liveEnvelopes(f.org.ID, ws); n != 0 {
		t.Fatalf("%d envelopes of the removed workspace open after a racing write", n)
	}
	if n := f.meshRows(ws)["mesh_installations"]; n != 0 {
		t.Fatal("the installation survived the removal")
	}
}

// A failed install can leave sealed credentials under a workspace with no
// installation row. A removal erases them too and still answers exactly like
// a workspace never installed.
func TestMeshUninstallErasesOrphanedCredentials(t *testing.T) {
	f := newMeshFixture(t, true)
	ctx := context.Background()
	orphan := uuid.New()
	vault := f.local.MeshVault()
	for _, kind := range []string{builtin.MeshExtensionToken, builtin.MeshEventsSecret} {
		if err := vault.Put(ctx, f.org.ID.String(), orphan.String(), kind, "orphan-"+kind); err != nil {
			t.Fatalf("seal orphan %s: %v", kind, err)
		}
	}
	if n := f.liveEnvelopes(f.org.ID, orphan); n != 2 {
		t.Fatalf("live orphan envelopes = %d, want 2", n)
	}
	got, never := f.uninstall(f.admin, orphan), f.uninstall(f.admin, uuid.New())
	wantStatus(t, got, http.StatusNotFound, "orphan removal")
	if stripRequestID(got.Body.String()) != stripRequestID(never.Body.String()) {
		t.Error("an orphaned workspace answers differently from one never installed")
	}
	if n := f.liveEnvelopes(f.org.ID, orphan); n != 0 {
		t.Fatalf("%d orphaned envelopes still open after the removal", n)
	}
}

// No removal without its record: if the journal refuses the pending record
// nothing is erased or deleted, and if it refuses the final record the
// answer is a 503, never an acknowledgement.
func TestMeshUninstallNoRemovalWithoutAuditRecord(t *testing.T) {
	f := newMeshFixture(t, true)
	ws := f.installedWorkspace()
	wantStatus(t, f.putSecret(ws, "db-password", "v-1"), http.StatusOK, "put")
	before := f.liveEnvelopes(f.org.ID, ws)

	f.refuseAudit("mesh.uninstall", "pending")
	if rec := f.uninstall(f.admin, ws); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("removal with a refusing journal = %d %s, want 503", rec.Code, answerDiag(rec))
	}
	if f.meshRows(ws)["mesh_installations"] != 1 || f.liveEnvelopes(f.org.ID, ws) != before {
		t.Fatal("a removal the journal refused changed the workspace")
	}
	f.dropAuditRefusal()

	f.refuseAudit("mesh.uninstall", "failed")
	if rec := f.uninstall(f.member, ws); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("refusal with a refusing journal = %d, want 503", rec.Code)
	}
	f.dropAuditRefusal()

	f.refuseAudit("mesh.uninstall", "ok")
	if rec := f.uninstall(f.admin, ws); rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), `"erased"`) {
		t.Fatalf("removal with an unwritten final record = %d %s, want 503", rec.Code, answerDiag(rec))
	}
	f.dropAuditRefusal()
	// The refused pending record left nothing and a member's refusal writes
	// none: only the last attempt's pending record stands, without its outcome.
	if n := f.count(`SELECT count(*) FROM audit_records WHERE org_id = $1 AND action = 'mesh.uninstall' AND result_status = 'pending'`, f.org.ID.String()); n != 1 {
		t.Errorf("pending mesh.uninstall records = %d, want 1", n)
	}
	if n := f.count(`SELECT count(*) FROM audit_records WHERE org_id = $1 AND action = 'mesh.uninstall' AND result_status = 'ok'`, f.org.ID.String()); n != 0 {
		t.Errorf("ok mesh.uninstall records = %d, want 0", n)
	}
}
