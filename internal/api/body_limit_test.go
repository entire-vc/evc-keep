package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/identity"
	"github.com/entire-vc/evc-keep/internal/tenancy"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// rawDo sends body as is (no marshalling), optionally hiding its length from
// the server as a chunked upload would.
func (f *routeFixture) rawDo(path, bearer string, body io.Reader, unknownLength bool) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, body)
	if unknownLength {
		r.ContentLength = -1
	}
	r.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	f.router.ServeHTTP(rec, r)
	return rec
}

// padded returns a valid JSON object holding obj's fields, with total length
// exactly size bytes. With a field name the filler goes into that declared
// string field (the body is then only fit for a size check: the field holds
// junk); with "" the object is padded by trailing whitespace and stays valid.
func padded(t *testing.T, obj map[string]any, field, filler string, size int) []byte {
	t.Helper()
	base, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	if field == "" {
		if len(base) > size {
			t.Fatalf("size %d is below the base object (%d)", size, len(base))
		}
		return append(base, bytes.Repeat([]byte(" "), size-len(base))...)
	}
	obj[field] = ""
	if base, err = json.Marshal(obj); err != nil {
		t.Fatal(err)
	}
	pad := size - len(base)
	if pad < 0 {
		t.Fatalf("size %d is below the base object (%d)", size, len(base))
	}
	obj[field] = strings.Repeat(filler, pad)[:pad]
	out, err := json.Marshal(obj)
	if err != nil || len(out) != size {
		t.Fatalf("padded body: len=%d want %d err=%v", len(out), size, err)
	}
	return out
}

type bodyLimitCase struct {
	name  string
	path  func(f *routeFixture) string
	body  func(f *routeFixture, tb testing.TB) map[string]any
	limit int
	okCod int
	event string // log event a strictly refused body must produce
	field string // a declared string field of the body, for the over-limit filler
}

func bodyLimitCases(f *routeFixture) (bearer string, cases []bodyLimitCase) {
	admin := f.mustAdmin("admin")
	bearer = f.mustToken(identity.KindUser, admin.ID, "org:"+f.org.ID.String())
	f.mustStore("default", tenancy.Org(f.org.ID))
	agent := f.mustAgent(admin, "ci-agent")
	org := f.org.ID.String()
	return bearer, []bodyLimitCase{
		{
			name: "create-secret", path: func(*routeFixture) string { return "/orgs/" + org + "/secrets" },
			body: func(*routeFixture, testing.TB) map[string]any {
				return map[string]any{"scope_level": "org", "scope_id": org, "name": "n", "class": "credential", "type": "generic", "provider_ref": "builtin://default/n"}
			},
			limit: maxSecretBodyBytes, okCod: http.StatusCreated, event: "secret_create_rejected", field: "description",
		},
		{
			name: "issue-token", path: func(*routeFixture) string { return "/orgs/" + org + "/tokens" },
			body: func(*routeFixture, testing.TB) map[string]any {
				return map[string]any{"kind": "a", "principal_id": agent.ID.String(), "scope": "org:" + org}
			},
			limit: maxTokenBodyBytes, okCod: http.StatusCreated, event: "token_issue_rejected", field: "scope",
		},
	}
}

func TestBodyLimit_ExactLimitPassesOneOverIs413(t *testing.T) {
	f := newRouteFixture(t)
	bearer, cases := bodyLimitCases(f)
	c := canary.New()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			at := padded(t, tc.body(f, t), "", "", tc.limit)
			if rec := f.rawDo(tc.path(f), bearer, bytes.NewReader(at), false); rec.Code != tc.okCod {
				t.Fatalf("body of exactly the limit: status = %d, want %d, body = %s", rec.Code, tc.okCod, rec.Body.String())
			}
			over := padded(t, tc.body(f, t), tc.field, c.Value(1)+"-", tc.limit+1)
			rec := f.rawDo(tc.path(f), bearer, bytes.NewReader(over), false)
			assertTooLarge(t, rec, c)
		})
	}
}

func TestBodyLimit_StreamWithoutContentLengthStopsAtLimit(t *testing.T) {
	f := newRouteFixture(t)
	bearer, cases := bodyLimitCases(f)
	c := canary.New()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A valid prefix followed by an endless ignored string: the
			// handler must give up at the limit, not at the end of the stream.
			head := `{"` + tc.field + `":"` + c.Value(1)
			cr := &countingReader{r: io.MultiReader(strings.NewReader(head), &endless{})}
			rec := f.rawDo(tc.path(f), bearer, cr, true)
			assertTooLarge(t, rec, c)
			if cr.n > int64(tc.limit)+64<<10 {
				t.Fatalf("read %d bytes of an endless body, limit %d", cr.n, tc.limit)
			}
		})
	}
}

func TestBodyLimit_MalformedAndMultipleJSONAreInvalid(t *testing.T) {
	f := newRouteFixture(t)
	bearer, cases := bodyLimitCases(f)
	for _, tc := range cases {
		valid, _ := json.Marshal(tc.body(f, t))
		for name, body := range map[string][]byte{
			"truncated":      valid[:len(valid)-1],
			"not-json":       []byte("nonsense"),
			"two-objects":    append(append(append([]byte{}, valid...), ' '), valid...),
			"object-garbage": append(append([]byte{}, valid...), []byte(" x")...),
			"empty":          nil,
		} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				rec := f.rawDo(tc.path(f), bearer, bytes.NewReader(body), false)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
				}
				if !strings.Contains(rec.Body.String(), `"invalid_argument"`) {
					t.Fatalf("error_class is not invalid_argument: %s", rec.Body.String())
				}
			})
		}
		// Control: the same single object is accepted.
		if rec := f.rawDo(tc.path(f), bearer, bytes.NewReader(valid), false); rec.Code != tc.okCod {
			t.Fatalf("%s control: status = %d, want %d, body = %s", tc.name, rec.Code, tc.okCod, rec.Body.String())
		}
	}
}

func assertTooLarge(t *testing.T, rec *httptest.ResponseRecorder, c canary.Canary) {
	t.Helper()
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413, body = %.200s", rec.Code, rec.Body.String())
	}
	var e struct {
		ErrorClass string `json:"error_class"`
		Message    string `json:"message"`
		RequestID  string `json:"request_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || e.ErrorClass != "payload_too_large" || e.RequestID == "" {
		t.Fatalf("not the closed 413 error: %q err=%v", rec.Body.String(), err)
	}
	if c.In(rec.Body.String()) || c.In(rec.Header().Get("Content-Type")) {
		t.Fatal("canary from the rejected body reached the response")
	}
}

// endless yields a long run of 'a' (32 MiB: far above any limit, finite so a
// handler without a ceiling fails the test instead of hanging it).
type endless struct{ n int }

func (e *endless) Read(p []byte) (int, error) {
	if e.n >= 32<<20 {
		return 0, io.EOF
	}
	for i := range p {
		p[i] = 'a'
	}
	e.n += len(p)
	return len(p), nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// TestReadBoundedBody_NoDatabase keeps the ceiling guarded in a run without
// PostgreSQL: the helper needs no database, so these cases never skip.
func TestReadBoundedBody_NoDatabase(t *testing.T) {
	c := canary.New()
	call := func(body io.Reader) (*httptest.ResponseRecorder, []byte, bool) {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/x", body)
		r.ContentLength = -1
		got, refused := readBoundedBody(rec, r, 64, "req-1")
		return rec, got, refused == nil
	}
	if !c.In("x"+c.Value(1)) || c.In("nothing") { // positive control
		t.Fatal("canary detector is blind")
	}
	if rec, got, ok := call(strings.NewReader(strings.Repeat("a", 64))); !ok || len(got) != 64 || rec.Code != http.StatusOK {
		t.Fatalf("exactly the limit: ok=%v len=%d code=%d", ok, len(got), rec.Code)
	}
	over := c.Value(1) + strings.Repeat("a", 64)
	rec, got, ok := call(strings.NewReader(over))
	if ok || got != nil {
		t.Fatalf("one over the limit was accepted: ok=%v len=%d", ok, len(got))
	}
	assertTooLarge(t, rec, c)
	cr := &countingReader{r: &endless{}}
	rec, _, ok = call(cr)
	if ok || rec.Code != http.StatusRequestEntityTooLarge || cr.n > 64+64<<10 {
		t.Fatalf("endless stream: ok=%v code=%d read=%d", ok, rec.Code, cr.n)
	}
}

// TestStrictBody_UnknownFieldIs400 — an unknown field is refused with the
// fixed invalid_argument error on both free-form create routes, whatever its
// value, and neither the value nor the field name reaches the response, the
// log or the audit journal.
func TestStrictBody_UnknownFieldIs400(t *testing.T) {
	f := newRouteFixture(t)
	bearer, cases := bodyLimitCases(f)
	c := canary.New()
	for _, tc := range cases {
		for name, extra := range map[string]map[string]any{
			"value-canary": {"extra": c.Value(1)},
			"name-canary":  {c.Value(2): "x"},
			"nested":       {"extra": map[string]any{"deep": c.Value(3)}},
			"secret-alias": {"value": c.Value(4)},
		} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				body := tc.body(f, t)
				for k, v := range extra {
					body[k] = v
				}
				auditCount := func() (n int) {
					if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_records WHERE org_id = $1`, f.org.ID.String()).Scan(&n); err != nil {
						t.Fatalf("count audit_records: %v", err)
					}
					return n
				}
				before := auditCount()
				rec := f.do(http.MethodPost, tc.path(f), bearer, body)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400, body = %.200s", rec.Code, rec.Body.String())
				}
				var e struct {
					ErrorClass string `json:"error_class"`
					Message    string `json:"message"`
					RequestID  string `json:"request_id"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil || e.ErrorClass != "invalid_argument" || e.RequestID == "" {
					t.Fatalf("not the closed 400 error: %q err=%v", rec.Body.String(), err)
				}
				if strings.Contains(rec.Body.String(), "extra") || strings.Contains(rec.Body.String(), "unknown") {
					t.Fatalf("error names the rejected field: %s", rec.Body.String())
				}
				for _, v := range []string{rec.Body.String(), f.logbuf.String()} {
					if c.In(v) {
						t.Fatal("canary from the rejected body leaked")
					}
				}
				if n := auditCount() - before; n != 0 {
					t.Fatalf("a rejected body wrote %d audit records", n)
				}
				if !strings.Contains(f.logbuf.String(), tc.event) {
					t.Fatalf("no %s log event for the rejected body", tc.event)
				}
			})
		}
		// Control: the same body without the extra field is accepted.
		if rec := f.do(http.MethodPost, tc.path(f), bearer, tc.body(f, t)); rec.Code != tc.okCod {
			t.Fatalf("%s control: status = %d, want %d, body = %s", tc.name, rec.Code, tc.okCod, rec.Body.String())
		}
	}
}

// TestDecodeStrict_NoDatabase keeps strict decoding guarded in a run without
// PostgreSQL.
func TestDecodeStrict_NoDatabase(t *testing.T) {
	c := canary.New()
	type body struct {
		A string `json:"a"`
	}
	var ok body
	if err := decodeStrict([]byte(`{"a":"x"}`), &ok); err != nil || ok.A != "x" { // positive control
		t.Fatalf("valid body refused: %v", err)
	}
	for name, raw := range map[string]string{
		"unknown":  `{"a":"x","` + c.Value(1) + `":"` + c.Value(2) + `"}`,
		"trailing": `{"a":"x"} {"a":"y"}`,
		"garbage":  `{"a":"x"} x`,
		"empty":    ``,
	} {
		err := decodeStrict([]byte(raw), &body{})
		if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if c.In(err.Error()) || strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("%s: error echoes the body: %v", name, err)
		}
	}
}
