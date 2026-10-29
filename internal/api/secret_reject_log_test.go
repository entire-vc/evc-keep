package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// auditRowCount is the number of R-AUD-1 rows written for the fixture's org.
func (f *routeFixture) auditRowCount() int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_records WHERE org_id = $1`, f.org.ID.String()).Scan(&n); err != nil {
		f.t.Fatalf("count audit_records: %v", err)
	}
	return n
}

// rejectLogLines returns the secret_create_rejected log records, decoded.
func rejectLogLines(t *testing.T, logs string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		if !strings.Contains(line, "secret_create_rejected") {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %v", err)
		}
		out = append(out, m)
	}
	return out
}

// Threat model §4.2 R-AUD-1, decision on #bc2d36db: a refused request body
// (413, 400) is not an event over a secret — no audit record — but leaves
// one structured log record on the closed key set and never carries the body.
func TestCreateSecretBodyRefusals_LogNotAudit(t *testing.T) {
	c := canary.New()
	if !c.In("x"+c.Value(1)) || !c.In(strings.ToUpper(c.Value(1))) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	f := newRouteFixture(t)
	admin := f.mustAdmin("admin")
	bearer := f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String())
	f.mustStore("default", tenancy.Org(f.org.ID))
	org := f.org.ID.String()
	path := "/orgs/" + org + "/secrets"
	valid := map[string]any{"scope_level": "org", "scope_id": org, "name": "n", "class": "credential", "type": "generic", "provider_ref": "builtin://default/n"}
	with := func(k string, v any) []byte {
		m := map[string]any{}
		for kk, vv := range valid {
			m[kk] = vv
		}
		m[k] = v
		b, _ := json.Marshal(m)
		return b
	}

	cases := []struct {
		name   string
		body   []byte
		status int
		class  string
	}{
		{"413-too-large", padded(t, map[string]any{}, "description", c.Value(1)+"-", maxSecretBodyBytes+1), http.StatusRequestEntityTooLarge, "payload_too_large"},
		{"400-truncated-json", []byte(`{"name":"` + c.Value(2)), http.StatusBadRequest, "invalid_argument"},
		{"400-missing-class-canary-name", with("class", ""), http.StatusBadRequest, "invalid_argument"},
		{"400-bad-provider-ref", with("provider_ref", c.Value(4)), http.StatusBadRequest, "invalid_argument"},
		{"400-bad-utf8", append([]byte(`{"name":"`+c.Value(5)+`\xff`), 0xff, '"', '}'), http.StatusBadRequest, "invalid_argument"},
	}
	// the "missing class" case carries the canary as the (untrusted) name
	for i := range cases {
		if cases[i].name == "400-missing-class-canary-name" {
			cases[i].body = with("name", c.Value(6))
			var m map[string]any
			_ = json.Unmarshal(cases[i].body, &m)
			m["class"] = ""
			cases[i].body, _ = json.Marshal(m)
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			beforeRows := f.auditRowCount()
			f.logbuf.Reset()
			rec := f.rawDo(path, bearer, bytes.NewReader(tc.body), false)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			var eb struct {
				ErrorClass string `json:"error_class"`
				RequestID  string `json:"request_id"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &eb); err != nil || eb.ErrorClass != tc.class || eb.RequestID == "" {
				t.Fatalf("error body = %s (err %v)", rec.Body.String(), err)
			}
			if got := f.auditRowCount(); got != beforeRows {
				t.Fatalf("audit rows %d -> %d: a refused body must not be a secret event", beforeRows, got)
			}
			lines := rejectLogLines(t, f.logbuf.String())
			if len(lines) != 1 {
				t.Fatalf("want exactly one secret_create_rejected record, got %d in:\n%s", len(lines), f.logbuf.String())
			}
			l := lines[0]
			if l["request_id"] != eb.RequestID || l["error_class"] != tc.class || l["status"] != float64(tc.status) {
				t.Errorf("record = %v, want request_id %q class %q status %d", l, eb.RequestID, tc.class, tc.status)
			}
			if l["org_id"] != org || l["principal_id"] != admin.ID.String() {
				t.Errorf("record = %v, want org_id %s principal_id %s", l, org, admin.ID)
			}
			if bl, ok := l["body_len"].(float64); !ok || bl < 0 || int(bl) > len(tc.body) {
				t.Errorf("body_len = %v (%T), want a byte count within [0,%d]", l["body_len"], l["body_len"], len(tc.body))
			}
			for k := range l {
				switch k {
				case "time", "level", "msg", "request_id", "error_class", "org_id", "principal_id", "status", "body_len":
				default:
					t.Errorf("unexpected key %q in a refusal record: %v", k, l)
				}
			}
			if c.In(f.logbuf.String()) {
				t.Errorf("canary leaked into the log: %s", f.logbuf.String())
			}
			if c.In(rec.Body.String()) || c.In(strings.Join(rec.Header().Values("Content-Type"), " ")) {
				t.Errorf("canary leaked into the response: %s", rec.Body.String())
			}
		})
	}
}

// Positive control for the test above: a refusal on rights IS journaled,
// exactly once, so "0 rows" for a body refusal is not "journal unplugged".
func TestCreateSecretPolicyDenial_IsAuditedOnce(t *testing.T) {
	f := newRouteFixture(t)
	admin := f.mustAdmin("admin")
	f.mustStore("default", tenancy.Org(f.org.ID))
	outsider := f.mustUser("outsider") // no membership: no create_ref
	bearer := f.mustToken(identity.KindUser, outsider.ID, "org:"+f.org.ID.String())
	_ = admin
	org := f.org.ID.String()
	before := f.auditRowCount()
	rec := f.do(http.MethodPost, "/orgs/"+org+"/secrets", bearer, map[string]any{
		"scope_level": "org", "scope_id": org, "name": "n", "class": "credential", "type": "generic", "provider_ref": "builtin://default/n",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", rec.Code, rec.Body.String())
	}
	if got := f.auditRowCount(); got != before+1 {
		t.Fatalf("audit rows %d -> %d, want exactly one new record for a rights denial", before, got)
	}
	var class string
	if err := f.pool.QueryRow(f.ctx, `SELECT result_error_class FROM audit_records WHERE org_id = $1 LIMIT 1`, org).Scan(&class); err != nil || class == "" {
		t.Fatalf("denial record has no error class: %q %v", class, err)
	}
	if n := len(rejectLogLines(t, f.logbuf.String())); n != 0 {
		t.Errorf("a rights denial must not be logged as a body refusal, got %d records", n)
	}
}
