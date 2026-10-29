package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/audit"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// auditVerifyWire is the response keep audit verify --json must echo: the
// closed field list of threat model §4.3, nothing
// more. Decoding with DisallowUnknownFields below is what makes an extra
// field a test failure rather than a silent pass.
type auditVerifyWire struct {
	OK             bool   `json:"ok"`
	RequestID      string `json:"request_id"`
	Checked        int64  `json:"checked"`
	BrokenID       string `json:"broken_id"`
	BrokenPosition int64  `json:"broken_position"`
	BreakKind      string `json:"break_kind"`
}

func (e *testEnv) appendAudit(n int, mutate func(i int, r *audit.Record)) []audit.Record {
	e.t.Helper()
	j := audit.NewJournal(e.pool)
	var out []audit.Record
	for i := 0; i < n; i++ {
		r := audit.Record{
			OrgID:  e.org.ID.String(),
			Actor:  audit.Actor{Type: audit.ActorSystem, ID: "test-actor", Via: audit.ViaCLI},
			Action: audit.ActionSecretCreateRef,
			Result: audit.Result{Status: audit.StatusOK},
		}
		if mutate != nil {
			mutate(i, &r)
		}
		got, err := j.Append(e.ctx, r)
		if err != nil {
			e.t.Fatalf("append audit record %d: %v", i, err)
		}
		out = append(out, got)
	}
	return out
}

func decodeAuditVerifyJSON(t *testing.T, s string) auditVerifyWire {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	var w auditVerifyWire
	if err := dec.Decode(&w); err != nil {
		t.Fatalf("decode --json output as the closed §4.3 shape: %v\n%s", err, s)
	}
	return w
}

func TestCLI_AuditVerify_CleanChain(t *testing.T) {
	e := newTestEnv(t)
	admin := e.mustAdmin("admin")
	env := withToken(e.mustToken(admin.ID, tenancy.Org(e.org.ID)))
	e.appendAudit(3, nil)

	r := e.runKeep(env, "audit", "verify", "--json")
	if r.exitCode != 0 {
		t.Fatalf("exit = %d, stderr = %s", r.exitCode, r.stderr)
	}
	w := decodeAuditVerifyJSON(t, r.stdout)
	if !w.OK || w.Checked != 3 || w.BrokenID != "" || w.BreakKind != "" {
		t.Fatalf("got %+v, want ok=true checked=3 and no break fields", w)
	}

	tbl := e.runKeep(env, "audit", "verify")
	if tbl.exitCode != 0 || !strings.Contains(tbl.stdout, "ok:") || !strings.Contains(tbl.stdout, "true") || !strings.Contains(tbl.stdout, "checked:") {
		t.Fatalf("table output: exit=%d stdout=%q stderr=%q", tbl.exitCode, tbl.stdout, tbl.stderr)
	}
	if strings.Contains(tbl.stdout, "broken_id") {
		t.Errorf("clean chain table mentions broken_id: %q", tbl.stdout)
	}
}

func TestCLI_AuditVerify_TamperedChain(t *testing.T) {
	e := newTestEnv(t)
	admin := e.mustAdmin("admin")
	env := withToken(e.mustToken(admin.ID, tenancy.Org(e.org.ID)))
	recs := e.appendAudit(3, nil)
	// Tamper as the pool's own login role, bypassing the journal entirely.
	if _, err := e.pool.Exec(context.Background(),
		`UPDATE audit_records SET actor_id = 'tampered-actor' WHERE id = $1`, recs[1].ID); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	r := e.runKeep(env, "audit", "verify", "--json")
	if r.exitCode != 1 {
		t.Fatalf("a broken chain must exit 1, got %d (stderr %q)", r.exitCode, r.stderr)
	}
	w := decodeAuditVerifyJSON(t, r.stdout)
	if w.OK || w.BreakKind != "hash" || w.BrokenID != recs[1].ID || w.BrokenPosition == 0 {
		t.Fatalf("got %+v, want ok=false break_kind=hash broken_id=%s broken_position>0", w, recs[1].ID)
	}

	tbl := e.runKeep(env, "audit", "verify")
	if tbl.exitCode != 1 || !strings.Contains(tbl.stdout, recs[1].ID) || !strings.Contains(tbl.stdout, "hash") {
		t.Fatalf("table output: exit=%d stdout=%q", tbl.exitCode, tbl.stdout)
	}
}

// Leak test: the token and a canary planted in journal free-text fields never
// reach stdout, stderr or the --debug trace of audit verify, on a clean and a
// tampered chain alike.
func TestCLI_AuditVerify_NeverLeaksTokenOrRecordContent(t *testing.T) {
	e := newTestEnv(t)
	admin := e.mustAdmin("admin")
	realToken := e.mustToken(admin.ID, tenancy.Org(e.org.ID))
	tc := canary.Of(realToken)
	env := withToken(realToken)

	rc := canary.New()
	if !rc.In(rc.Value(1)) || !tc.In(realToken) {
		t.Fatal("canary detector is blind; this test proves nothing")
	}
	recs := e.appendAudit(2, func(i int, r *audit.Record) {
		r.Intent.Reason = rc.Value(1)
		r.Target.Path = rc.Value(2)
	})

	runs := []runResult{
		e.runKeep(env, "audit", "verify", "--debug"),
		e.runKeep(env, "audit", "verify", "--json", "--debug"),
	}
	if _, err := e.pool.Exec(context.Background(),
		`UPDATE audit_records SET actor_id = 'tampered-actor' WHERE id = $1`, recs[0].ID); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	runs = append(runs, e.runKeep(env, "audit", "verify", "--json", "--debug"))

	sawDebug := false
	for i, r := range runs {
		for name, s := range map[string]string{"stdout": r.stdout, "stderr": r.stderr} {
			// Never print the stream: --debug runs carry the real token.
			if tc.In(s) {
				t.Fatalf("run %d: the token appears in %s (%d bytes)", i, name, len(s))
			}
			if rc.In(s) {
				t.Fatalf("run %d: journal record content appears in %s (%d bytes)", i, name, len(s))
			}
		}
		if strings.Contains(r.stderr, "[debug]") {
			sawDebug = true
			if !strings.Contains(r.stderr, "[REDACTED]") {
				t.Fatalf("run %d: --debug trace has no [REDACTED] marker", i)
			}
		}
	}
	if !sawDebug {
		t.Fatal("no run produced [debug] output; the redaction path was never exercised")
	}
}

// A server error is reported by class and message from the closed error body
// only; a non-JSON error body (a proxy page, a stack trace) is never echoed.
func TestCLI_AuditVerify_ServerErrorTextIsNotPropagated(t *testing.T) {
	e := newTestEnv(t)
	c := canary.New()
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("panic: " + c.Value(1)))
	}))
	t.Cleanup(stub.Close)

	// Positive control: the canary is detectable in the very bytes the stub sends.
	if !c.In("panic: " + c.Value(1)) {
		t.Fatal("canary detector is blind to its own value")
	}
	r := e.runKeepAt(stub.URL, withToken("t-stub"), "audit", "verify")
	if r.exitCode != 1 {
		t.Fatalf("exit = %d, want 1", r.exitCode)
	}
	if r.stderr == "" {
		t.Fatal("no error reported at all")
	}
	if c.In(r.stderr) || c.In(r.stdout) {
		t.Fatalf("raw server error text reached the CLI output (%d/%d bytes)", len(r.stderr), len(r.stdout))
	}
}

func TestCLI_AuditVerify_UsageErrors(t *testing.T) {
	e := newTestEnv(t)
	for _, args := range [][]string{{"audit"}, {"audit", "bogus"}, {"audit", "verify", "extra"}} {
		r := e.runKeep(withToken("x"), args...)
		if r.exitCode != 2 {
			t.Errorf("%v: exit = %d, want 2 (stderr %q)", args, r.exitCode, r.stderr)
		}
	}
	if n := e.requests.Load(); n != 0 {
		t.Errorf("usage errors reached the server %d time(s)", n)
	}
}

// A server that answers outside the closed sets for broken_id/break_kind cannot
// push arbitrary bytes (terminal escapes, canary text) through the CLI.
func TestCLI_AuditVerify_FreeFormFieldsStayInsideClosedSets(t *testing.T) {
	e := newTestEnv(t)
	c := canary.New()
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"checked":3,"broken_id":"\u001b[2J` + c.Value(1) + `","broken_position":2,"break_kind":"\u001b[2J` + c.Value(1) + `","request_id":"\u001b[2J` + c.Value(1) + `"}`))
	}))
	t.Cleanup(stub.Close)

	for _, args := range [][]string{{"audit", "verify"}, {"audit", "verify", "--json"}} {
		r := e.runKeepAt(stub.URL, withToken("t-stub"), args...)
		if r.exitCode != 1 {
			t.Fatalf("%v: exit = %d, want 1", args, r.exitCode)
		}
		if c.In(r.stdout) || c.In(r.stderr) || strings.ContainsRune(r.stdout, 0x1b) {
			t.Fatalf("%v: off-list server text reached the output (%d bytes)", args, len(r.stdout))
		}
	}
}
