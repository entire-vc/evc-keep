package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/obs"
	"github.com/entire-vc/evc-keep/internal/restart"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const restartFP = "kfp1:k1:abcdefghijklmnop"

type restartEnv struct {
	db     *pgxpool.Pool
	org    uuid.UUID
	repo   *restart.Repo
	h      http.Handler
	log    *bytes.Buffer
	poller string
}

func newRestartEnv(t *testing.T) restartEnv {
	t.Helper()
	db := testPool(t)
	org := seedOrg(t, db)
	var buf bytes.Buffer
	repo := restart.NewRepo(db)
	return restartEnv{
		db: db, org: org, repo: repo, log: &buf,
		h:      NewRouter(obs.New(&buf), db, Deps{Restarts: repo}),
		poller: pollerToken(t, db, org, PollerScopePrefix+":"+org.String()),
	}
}

// pollerToken seeds a service and returns its bearer token with the given scope.
func pollerToken(t *testing.T, db *pgxpool.Pool, org uuid.UUID, scope string) string {
	t.Helper()
	svc := uuid.New()
	if _, err := db.Exec(context.Background(), `INSERT INTO services (id, org_id, owner_scope, name) VALUES ($1, $2, $3, $4)`,
		svc, org, tenancy.Org(org).String(), "poller-"+svc.String()); err != nil {
		t.Fatalf("seed service: %v", err)
	}
	res, err := identity.NewRepo(db).Issue(context.Background(), identity.IssueParams{
		OrgID: org, Kind: identity.KindService, PrincipalID: svc, Scope: scope,
	})
	if err != nil {
		t.Fatalf("issue poller token: %v", err)
	}
	return identity.Reveal(res.Token)
}

func (e restartEnv) do(method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e restartEnv) claim(t *testing.T) []map[string]any {
	t.Helper()
	rec := e.do("POST", "/v1/restarts/claim", e.poller, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", rec.Code, rec.Body)
	}
	var got []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("claim body: %v", err)
	}
	return got
}

func TestRestartClaimReturnsExactlyTheClosedFieldsOnce(t *testing.T) {
	e := newRestartEnv(t)
	id, err := e.repo.Enqueue(context.Background(), e.org, "Hugh", "key-7", restartFP)
	if err != nil {
		t.Fatal(err)
	}
	got := e.claim(t)
	if len(got) != 1 || len(got[0]) != 5 || len(got[0]["claim_token"].(string)) != 32 || got[0]["request_id"] != id.String() || got[0]["lane"] != "Hugh" ||
		got[0]["key_version"] != "key-7" || got[0]["fingerprint"] != restartFP {
		t.Fatalf("claim: %v", got)
	}
	if again := e.claim(t); len(again) != 0 {
		t.Fatalf("second claim: %v", again)
	}
	if rec := e.do("POST", "/v1/restarts/claim", e.poller, ""); strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty claim must be [], got %q", rec.Body)
	}
}

func TestRestartRoutesNeedThePollerRole(t *testing.T) {
	e := newRestartEnv(t)
	id, _ := e.repo.Enqueue(context.Background(), e.org, "Hugh", "key-7", restartFP)
	other := seedOrg(t, e.db)
	tokens := map[string]string{
		"org admin user":         adminToken(t, e.db, e.org),
		"service, no role":       pollerToken(t, e.db, e.org, tenancy.Org(e.org).String()),
		"service, other org":     pollerToken(t, e.db, e.org, PollerScopePrefix+":"+other.String()),
		"service, role of other": pollerToken(t, e.db, e.org, "restart_poller:"+e.org.String()),
	}
	for name, tok := range tokens {
		for _, rt := range [][2]string{{"/v1/restarts/claim", ""}, {"/v1/restarts/" + id.String() + "/ack", `{"result":"ok","claim_token":"` + strings.Repeat("ab", 16) + `"}`}} {
			rec := e.do("POST", rt[0], tok, rt[1])
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s on %s: %d, want 403", name, rt[0], rec.Code)
			}
		}
	}
	if rec := e.do("POST", "/v1/restarts/claim", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if got := e.claim(t); len(got) != 1 {
		t.Fatalf("a refused caller must not have consumed the request: %v", got)
	}
}

func TestRestartPollerTokenReachesNothingElse(t *testing.T) {
	e := newRestartEnv(t)
	org, sid := e.org.String(), uuid.NewString()
	// Bodies are well formed and ids valid so a request that got past the role
	// gate would answer 200/400/404 from its handler instead of 403.
	deploy := `{"secret":"any","runner_id":"` + uuid.NewString() + `"}`
	for _, rt := range [][3]string{
		{"GET", "/orgs/" + org + "/secrets?scope_level=org&scope_id=" + org, ""},
		{"POST", "/orgs/" + org + "/secrets", "{}"},
		{"GET", "/orgs/" + org + "/secrets/" + sid, ""},
		{"GET", "/orgs/" + org + "/secrets/" + sid + "/versions", ""},
		{"GET", "/orgs/" + org + "/secrets/" + sid + "/carriers", ""},
		{"POST", "/orgs/" + org + "/secrets/" + sid + "/rotate", "{}"},
		{"POST", "/orgs/" + org + "/tokens", "{}"},
		{"POST", "/orgs/" + org + "/tokens/" + uuid.NewString() + "/revoke", ""},
		{"GET", "/orgs/" + org + "/audit/verify", ""},
		{"POST", "/v1/deployments", deploy},
		{"GET", "/v1/deployments/" + uuid.NewString(), ""},
		{"POST", "/v1/input-links", "{}"},
		{"POST", "/v1/carriers/verify", "{}"},
		{"POST", "/runners/enroll-tokens", "{}"},
		{"POST", "/runners/" + uuid.NewString() + "/revoke", ""},
	} {
		rec := e.do(rt[0], rt[1], e.poller, rt[2])
		// 404 is allowed for routes the test router leaves unwired; 200 never is.
		if rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound && rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with the poller token: %d, want 401/403/404", rt[0], rt[1], rec.Code)
		}
	}
	// The catalog routes are wired here: the gate must answer, not the handler.
	for _, rt := range [][2]string{
		{"GET", "/orgs/" + org + "/secrets?scope_level=org&scope_id=" + org},
		{"POST", "/orgs/" + org + "/tokens"},
		// Public and unregistered routes answer the gate too.
		{"GET", "/healthz"},
		{"GET", "/readyz"},
		{"GET", "/no/such/route"},
		// The install routes take their own authentication path; the gate
		// still answers before it.
		{"POST", "/mesh/install"},
		{"POST", "/orgs/" + org + "/mesh/pending-installs"},
	} {
		if rec := e.do(rt[0], rt[1], e.poller, "{}"); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s: %d, want 403 from the role gate", rt[0], rt[1], rec.Code)
		}
	}
}

func TestRestartAck(t *testing.T) {
	e := newRestartEnv(t)
	id, _ := e.repo.Enqueue(context.Background(), e.org, "Test", "key-7", restartFP)
	path := "/v1/restarts/" + id.String() + "/ack"
	body := func(result, tok string) string { return `{"result":"` + result + `","claim_token":"` + tok + `"}` }
	if rec := e.do("POST", path, e.poller, body("ok", strings.Repeat("ab", 16))); rec.Code != http.StatusNotFound {
		t.Fatalf("ack before claim: %d", rec.Code)
	}
	tok := e.claim(t)[0]["claim_token"].(string)
	if rec := e.do("POST", path, e.poller, body("bogus", tok)); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad result: %d", rec.Code)
	}
	if rec := e.do("POST", path, e.poller, `{"result":"ok","claim_token":"`+tok+`","extra":1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("extra field: %d", rec.Code)
	}
	// A missing or wrong token is as unknown as a random id, and closes nothing.
	for name, b := range map[string]string{
		"missing": `{"result":"ok"}`,
		"wrong":   body("ok", strings.Repeat("cd", 16)),
		"short":   body("ok", "ab"),
	} {
		if rec := e.do("POST", path, e.poller, b); rec.Code != http.StatusNotFound {
			t.Fatalf("%s: %d, want 404", name, rec.Code)
		}
	}
	for i := 0; i < 2; i++ {
		if rec := e.do("POST", path, e.poller, body("nothing_running", tok)); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
			t.Fatalf("ack #%d: %d %q", i, rec.Code, rec.Body)
		}
	}
	if rec := e.do("POST", path, e.poller, body("failed", tok)); rec.Code != http.StatusConflict {
		t.Fatalf("other result: %d", rec.Code)
	}
	for _, p := range []string{"/v1/restarts/" + uuid.NewString() + "/ack", "/v1/restarts/not-a-uuid/ack"} {
		rec := e.do("POST", p, e.poller, body("ok", tok))
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "not-a-uuid") {
			t.Fatalf("unknown id %s: %d %s", p, rec.Code, rec.Body)
		}
	}
	// A request of another organization is as unknown as a random id.
	otherOrg := seedOrg(t, e.db)
	foreign, _ := e.repo.Enqueue(context.Background(), otherOrg, "Test", "key-7", restartFP)
	ftok, _ := e.repo.Claim(context.Background(), otherOrg, 10)
	rec := e.do("POST", "/v1/restarts/"+foreign.String()+"/ack", e.poller, body("ok", ftok[0].ClaimToken))
	unknown := e.do("POST", "/v1/restarts/"+uuid.NewString()+"/ack", e.poller, body("ok", ftok[0].ClaimToken))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("foreign ack: %d", rec.Code)
	}
	var a, b map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &a)
	_ = json.Unmarshal(unknown.Body.Bytes(), &b)
	if a["error_class"] != b["error_class"] || a["message"] != b["message"] {
		t.Fatalf("foreign and unknown ids answer differently: %v vs %v", a, b)
	}
}

func TestIssuePollerTokenScope(t *testing.T) {
	e := newRestartEnv(t)
	admin := adminToken(t, e.db, e.org)
	svc := uuid.New()
	if _, err := e.db.Exec(context.Background(), `INSERT INTO services (id, org_id, owner_scope, name) VALUES ($1, $2, $3, 'p')`,
		svc, e.org, tenancy.Org(e.org).String()); err != nil {
		t.Fatal(err)
	}
	issue := func(kind, principal, scope string) int {
		body, _ := json.Marshal(map[string]string{"kind": kind, "principal_id": principal, "scope": scope})
		return e.do("POST", "/orgs/"+e.org.String()+"/tokens", admin, string(body)).Code
	}
	if c := issue("s", svc.String(), PollerScopePrefix+":"+e.org.String()); c != http.StatusCreated {
		t.Fatalf("service poller token: %d", c)
	}
	if c := issue("a", uuid.NewString(), PollerScopePrefix+":"+e.org.String()); c != http.StatusBadRequest {
		t.Fatalf("agent with the poller scope: %d", c)
	}
	if c := issue("s", svc.String(), PollerScopePrefix+":"+uuid.NewString()); c != http.StatusBadRequest {
		t.Fatalf("poller scope of another org: %d", c)
	}
}

// TestRestartSurfacesNeverCarryAValue is the leak test of the new surface. No
// route takes a value, so the canary is planted wherever a caller can put text:
// a ack result, an id, a body field, the token. Neither the bodies, headers nor
// logs of any answer may carry it, successful ones included; only the claim
// that hands a token out may show that token.
func TestRestartSurfacesNeverCarryAValue(t *testing.T) {
	e := newRestartEnv(t)
	c := canary.New()
	if !c.In("x"+c.Value(1)) || !c.In(strings.ToUpper(c.Value(1))) {
		t.Fatal("canary detector is blind")
	}
	id, _ := e.repo.Enqueue(context.Background(), e.org, "Hugh", "key-7", restartFP)
	var out, issued strings.Builder
	capture := func(b *strings.Builder, rec *httptest.ResponseRecorder) {
		b.WriteString(rec.Body.String())
		for k, v := range rec.Header() {
			b.WriteString(k + strings.Join(v, ","))
		}
	}
	grab := func(rec *httptest.ResponseRecorder) { capture(&out, rec) }
	first := e.do("POST", "/v1/restarts/claim", e.poller, c.Value(9))
	var handed []map[string]any
	if first.Code != http.StatusOK || json.Unmarshal(first.Body.Bytes(), &handed) != nil || len(handed) != 1 {
		t.Fatalf("first claim: %d", first.Code)
	}
	tok := handed[0]["claim_token"].(string)
	capture(&issued, first)
	grab(e.do("POST", "/v1/restarts/"+id.String()+"/ack", e.poller, `{"result":"`+c.Value(1)+`"}`))
	grab(e.do("POST", "/v1/restarts/"+id.String()+"/ack", e.poller, `{"`+c.Value(2)+`":"ok"}`))
	grab(e.do("POST", "/v1/restarts/"+c.Value(3)+"/ack", e.poller, `{"result":"ok"}`))
	grab(e.do("POST", "/v1/restarts/"+id.String()+"/ack", e.poller, `{"result":"ok","claim_token":"`+c.Value(7)+`"}`))
	// A wrong-token ack of a live claim must not echo the live token or the
	// given one, in the answer or in the log.
	wrong := e.do("POST", "/v1/restarts/"+id.String()+"/ack", e.poller, `{"result":"ok","claim_token":"`+strings.Repeat("0", 32)+`"}`)
	grab(wrong)
	grab(e.do("POST", "/v1/restarts/claim", c.Value(4), ""))
	grab(e.do("POST", "/v1/restarts/claim", e.poller, c.Value(5)))
	// One field at a time: a refused lane returns before the other checks, so
	// version and fingerprint get their own probes with an allowed lane.
	for name, in := range map[string][3]string{
		"lane":        {c.Value(6), "key-7", restartFP},
		"version":     {"Hugh", c.Value(6) + "!", restartFP},
		"fingerprint": {"Hugh", "key-7", "kfp1:k1:" + c.Value(6)},
	} {
		_, err := e.repo.Enqueue(context.Background(), e.org, in[0], in[1], in[2])
		if err == nil {
			t.Fatalf("%s probe: a value-shaped field was accepted", name)
		}
		out.WriteString(err.Error())
	}
	// A successful claim is the one answer that carries request fields; it is
	// checked with the rest.
	if _, err := e.repo.Enqueue(context.Background(), e.org, "Hugh", "key-8", restartFP); err != nil {
		t.Fatal("enqueue for the claim probe")
	}
	claimed := e.do("POST", "/v1/restarts/claim", e.poller, c.Value(8))
	var second []map[string]any
	if claimed.Code != http.StatusOK || json.Unmarshal(claimed.Body.Bytes(), &second) != nil || len(second) != 1 || second[0]["key_version"] != "key-8" {
		t.Fatalf("claim probe did not hand out the request: %d", claimed.Code)
	}
	tok2 := second[0]["claim_token"].(string)
	// Each token shows up in its own claim only: the second claim must not
	// repeat the first token, and the tokens must differ.
	if tok == tok2 || strings.Contains(claimed.Body.String(), tok) || strings.Contains(first.Body.String(), tok2) {
		t.Fatal("a claim showed another claim's token")
	}
	capture(&issued, claimed)
	// The accepted ack and its repeat answer too.
	for range 2 {
		ok := e.do("POST", "/v1/restarts/"+id.String()+"/ack", e.poller, `{"result":"ok","claim_token":"`+tok+`"}`)
		if ok.Code != http.StatusNoContent {
			t.Fatalf("ack with the live token: %d", ok.Code)
		}
		grab(ok)
	}
	if out.Len() == 0 || e.log.Len() == 0 {
		t.Fatal("nothing was captured, the test proves nothing")
	}
	for _, tk := range []string{tok, tok2} {
		if strings.Contains(out.String(), tk) || strings.Contains(e.log.String(), tk) {
			t.Fatalf("the claim token reached an answer other than its claim, or the log")
		}
	}
	last := e.do("POST", "/v1/restarts/claim", e.poller, c.Value(10))
	if last.Code != http.StatusOK {
		t.Fatalf("empty claim: %d", last.Code)
	}
	if strings.Contains(last.Body.String(), tok) || strings.Contains(last.Body.String(), tok2) {
		t.Fatal("a later claim showed an earlier claim token")
	}
	capture(&issued, last)
	all := out.String() + issued.String()
	if c.In(all) || c.In(e.log.String()) {
		t.Fatalf("canary reached a response or the log:\n%s\n%s", all, e.log.String())
	}
	if strings.Contains(all, "secret") {
		t.Fatalf("an answer names a secret: %s", all)
	}
}
