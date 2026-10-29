package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/entire-vc/evc-keep/internal/testutil/pgscratch"
)

// mustDecodeAuditVerify unmarshals rec's body as the route's own response
// type, failing the test on malformed JSON — every case below needs the
// same decode, only the assertions on the result differ.
func mustDecodeAuditVerify(t *testing.T, rec *httptest.ResponseRecorder) AuditVerifyResult {
	t.Helper()
	var body AuditVerifyResult
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal audit verify response: %v\nbody: %s", err, rec.Body.String())
	}
	return body
}

// newAuditRecord builds a minimal valid Record for org — Append fills ID,
// TS and PrevHash itself, see [audit.Journaler.Append]'s own doc. mutate,
// if non-nil, edits the record before Append sees it — the same pattern
// internal/audit's own newRecord test helper uses, kept local here rather
// than exported, since only this file (and no other package) needs to
// mint raw journal records against a real database.
func newAuditRecord(org string, mutate func(*audit.Record)) audit.Record {
	r := audit.Record{
		OrgID:  org,
		Actor:  audit.Actor{Type: audit.ActorSystem, ID: "test-actor", Via: audit.ViaCLI},
		Action: audit.ActionSecretCreateRef,
		Result: audit.Result{Status: audit.StatusOK},
	}
	if mutate != nil {
		mutate(&r)
	}
	return r
}

// --- Leak test (written before the route existed — CONTRIBUTING.md /
// keep-leak-test-first): a canary planted in a journal record's free-text
// fields must never reach GET /orgs/{org_id}/audit/verify's response, even
// though the chain it belongs to verifies clean. audit.VerifyResult never
// carries a Record by construction (see verify.go's own doc) — this proves
// that empirically, against the real wire response, rather than trusting
// the type declaration alone.
func TestAuditVerify_CleanChainNeverCarriesRecordContent(t *testing.T) {
	f := newRouteFixture(t)
	user := f.mustUser("reader")
	bearer := f.mustToken(identity.KindUser, user.ID, "org:"+f.org.ID.String())

	c := canary.New()
	// Positive control (keep-leak-test-first): AuditVerifyResult has no
	// field a record's free-text could even reach, so c.In below can only
	// prove something if the detector itself still recognizes a planted
	// value — confirm that before trusting its silence.
	if !c.In(c.Value(1)) {
		t.Fatal("canary detector is blind to its own value; this test proves nothing")
	}
	j := audit.NewJournal(f.pool)
	if _, err := j.Append(f.ctx, newAuditRecord(f.org.ID.String(), func(r *audit.Record) {
		r.Intent.Reason = c.Value(1)
		r.Target.Path = c.Value(2)
	})); err != nil {
		t.Fatalf("Append: %v", err)
	}

	rec := f.do(http.MethodGet, "/orgs/"+f.org.ID.String()+"/audit/verify", bearer, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if c.In(rec.Body.String()) {
		t.Errorf("canary leaked into audit verify response: %s", rec.Body.String())
	}
	for k, vs := range rec.Header() {
		for _, v := range vs {
			if c.In(v) {
				t.Errorf("canary leaked into response header %s: %q", k, v)
			}
		}
	}
	if c.In(f.logbuf.String()) {
		t.Errorf("canary leaked into log output:\n%s", f.logbuf.String())
	}

	body := mustDecodeAuditVerify(t, rec)
	if !body.OK || body.Checked != 1 {
		t.Fatalf("got %+v, want ok=true checked=1", body)
	}
}

// --- Functional (AC1): a clean chain answers {ok:true, checked:N}; a
// chain tampered with directly in the database (bypassing Journal/keep_app
// entirely, the same "operator ran an ad hoc UPDATE" scenario
// internal/audit's own TestVerify_DetectsInPlaceTamper red-runs) answers
// {ok:false, break_kind:"hash", ...} naming the tampered record.
func TestAuditVerify_ReportsCleanAndTamperedChains(t *testing.T) {
	f := newRouteFixture(t)
	user := f.mustUser("reader")
	bearer := f.mustToken(identity.KindUser, user.ID, "org:"+f.org.ID.String())
	j := audit.NewJournal(f.pool)

	if _, err := j.Append(f.ctx, newAuditRecord(f.org.ID.String(), nil)); err != nil {
		t.Fatalf("Append #0: %v", err)
	}
	target, err := j.Append(f.ctx, newAuditRecord(f.org.ID.String(), nil))
	if err != nil {
		t.Fatalf("Append #1: %v", err)
	}
	if _, err := j.Append(f.ctx, newAuditRecord(f.org.ID.String(), nil)); err != nil {
		t.Fatalf("Append #2: %v", err)
	}

	clean := f.do(http.MethodGet, "/orgs/"+f.org.ID.String()+"/audit/verify", bearer, nil)
	if clean.Code != http.StatusOK {
		t.Fatalf("clean chain: status = %d, body = %s", clean.Code, clean.Body.String())
	}
	cleanBody := mustDecodeAuditVerify(t, clean)
	if !cleanBody.OK || cleanBody.Checked != 3 {
		t.Fatalf("clean chain: got %+v, want ok=true checked=3", cleanBody)
	}
	if strings.Contains(clean.Body.String(), "broken_id") {
		t.Errorf("clean chain response carries broken_id at all: %s", clean.Body.String())
	}

	// Bypass the application entirely — a direct UPDATE as the pool's own
	// login role, never through Journal/keep_app.
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE audit_records SET actor_id = 'tampered-actor' WHERE id = $1`, target.ID); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	tampered := f.do(http.MethodGet, "/orgs/"+f.org.ID.String()+"/audit/verify", bearer, nil)
	if tampered.Code != http.StatusOK {
		t.Fatalf("tampered chain: status = %d, body = %s", tampered.Code, tampered.Body.String())
	}
	tamperedBody := mustDecodeAuditVerify(t, tampered)
	if tamperedBody.OK {
		t.Fatalf("tampered chain reported ok=true: %+v", tamperedBody)
	}
	if tamperedBody.BreakKind != "hash" {
		t.Errorf("break_kind = %q, want %q", tamperedBody.BreakKind, "hash")
	}
	if tamperedBody.BrokenID != target.ID {
		t.Errorf("broken_id = %q, want the tampered record %q", tamperedBody.BrokenID, target.ID)
	}
	if tamperedBody.BrokenPosition == 0 {
		t.Error("broken_position = 0, want the tampered record's 1-based position")
	}
}

// --- AC2's red run: a record id can only ever be a ULID or the fixed
// "(malformed id)" placeholder in the response — [audit.Verify]'s own
// safeRecordID enforces this before this package ever sees BrokenID (see
// internal/audit's TestVerify_NeverReturnsAMalformedRecordID, which forges
// exactly this scenario at the audit-package layer). This test proves the
// same property end to end, through the real HTTP response this route
// answers with: this package's handler and [newAuditVerifyResult] must
// never re-introduce a leak by, say, formatting BrokenID differently or
// echoing some other raw column. Manually reverting safeRecordID's call in
// internal/audit/verify.go (using rec.ID instead) and re-running this test
// is this route's own red run for that guarantee — see the MR's "Red run"
// section for that output; it is not re-tested as a permanent mutation
// here because internal/audit's migration enforces the id shape at the
// database's own CHECK constraint, so this test lifts that constraint
// itself — on a scratch database, never the shared one — to reach the case
// at all.
func TestAuditVerify_BrokenIDIsNeverRaw(t *testing.T) {
	f := newRouteFixtureOn(t, scratchPool(t))
	user := f.mustUser("reader")
	bearer := f.mustToken(identity.KindUser, user.ID, "org:"+f.org.ID.String())
	j := audit.NewJournal(f.pool)

	first, err := j.Append(f.ctx, newAuditRecord(f.org.ID.String(), nil))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	pgscratch.DropConstraint(t, f.pool, "audit_records", "audit_records_id_shape")

	c := canary.New()
	badID := c.Value(1) + "\n\x1b[2Kchain OK"
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE forged ON COMMIT DROP AS SELECT * FROM audit_records WHERE id = $1`, first.ID); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE forged SET id = $1, org_seq = 2`, badID); err != nil {
		t.Fatalf("forge: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_records SELECT * FROM forged`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	rec := f.do(http.MethodGet, "/orgs/"+f.org.ID.String()+"/audit/verify", bearer, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	// json.Encoder.Encode appends exactly one trailing "\n" (see writeJSON) —
	// trim it before checking for an embedded newline or escape sequence, or
	// this assertion would fail on every response, forged id or not.
	raw := strings.TrimSuffix(rec.Body.String(), "\n")
	if c.In(raw) || strings.ContainsAny(raw, "\n\x1b") {
		t.Fatal("response carries the forged id's raw text")
	}
	body := mustDecodeAuditVerify(t, rec)
	if body.OK {
		t.Fatal("forged record verified ok=true")
	}
	if body.BrokenID != audit.MalformedID {
		t.Error("broken_id is not the fixed placeholder")
	}
}
