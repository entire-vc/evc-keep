package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// A server that, through a bug, answers with a value in extra fields and
// headers must not make any tool print it: answers are closed typed objects.
func TestNoCanaryInAnyToolAnswer(t *testing.T) {
	c := canary.New()
	value, token := c.Value(1), c.Value(2)
	requireDetectorSees(t, c, "x "+value, "x "+token)
	var s seen
	srv := restFake(t, value, &s)
	out := session(t, newTestServer(t, srv.URL, token), everyCall()...)
	// Fail closed: a reply with a field outside the closed list is refused whole.
	if strings.Count(out, "\n") != len(everyCall()) || strings.Count(out, `"isError":true`) != len(everyCall()) || !strings.Contains(out, "unexpected shape") {
		t.Fatalf("hostile replies were not refused (positive control): %q", out)
	}
	if !strings.Contains(s.all(), "/secrets") {
		t.Fatal("the fake server was never reached; the test proves nothing")
	}
	if c.In(out) {
		t.Fatalf("canary reached a tool answer: %s", out)
	}
}

// The bearer token and request details never appear in an error answer.
func TestErrorAnswersCarryOnlyClassAndTemplate(t *testing.T) {
	c := canary.New()
	value, token := c.Value(1), c.Value(2)
	for name, handler := range map[string]http.HandlerFunc{
		"error-with-extra-fields": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
			_ = json.NewEncoder(w).Encode(map[string]any{"error_class": "internal", "message": "boom", "request_id": testRequest, "debug": value})
		},
		"canary-in-message": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]any{"error_class": "invalid_argument", "message": "bad " + value, "request_id": testRequest})
		},
		"canary-as-class": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]any{"error_class": "x_" + strings.ToLower(value), "message": "m", "request_id": testRequest})
		},
		"unreadable-error": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(502)
			_, _ = w.Write([]byte("upstream said " + value))
		},
		"success-with-garbage": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not json " + value))
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(handler)
			defer srv.Close()
			out := session(t, newTestServer(t, srv.URL, token), everyCall()...)
			if strings.Count(out, "\n") != len(everyCall()) || !strings.Contains(out, `"isError":true`) {
				t.Fatalf("no error answers (positive control): %q", out)
			}
			if c.In(out) {
				t.Fatalf("canary reached an error answer: %s", out)
			}
		})
	}
	// A transport failure names a class only: not the address, not the token.
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close()
	out := session(t, newTestServer(t, base, token), everyCall()...)
	if c.In(out) || strings.Contains(out, strings.TrimPrefix(base, "http://")) {
		t.Fatalf("transport error leaked token or address: %s", out)
	}
}

// No tool accepts a value, and a value passed anyway reaches nobody.
func TestNoToolAcceptsAValue(t *testing.T) {
	c := canary.New()
	value := c.Value(1)
	var s seen
	srv := restFake(t, "", &s)
	srvr := newTestServer(t, srv.URL, "tok")
	listed := session(t, srvr, rpc(1, "tools/list", map[string]any{}))
	for _, forbidden := range []string{`"value"`, `"plaintext"`, `"secret_value"`, `"password"`, `"data"`} {
		if strings.Contains(listed, forbidden) {
			t.Fatalf("tool schema offers %s", forbidden)
		}
	}
	var lines []string
	for i, tc := range []struct {
		name string
		args map[string]any
	}{
		{"list_secrets", map[string]any{"scope_level": "org", "scope_id": testOrg}},
		{"get_secret_meta", map[string]any{"secret_id": testSecretID}},
		{"request_secret_input", map[string]any{"secret": "db-password"}},
		{"deploy", map[string]any{"secret": "db-password", "runner_id": testRunnerID,
			"target": map[string]any{"kind": "env-file", "path": "/etc/app/app.env", "uid": 1, "gid": 1}}},
		{"rotate", map[string]any{"secret_id": testSecretID, "mode": "generate"}},
	} {
		tc.args["value"] = value
		lines = append(lines, call(i+1, tc.name, tc.args))
	}
	lines = append(lines, call(6, "verify_carriers", map[string]any{"secret": "db-password", "value": value}))
	// A value nested in the target is as unwelcome as one at the top.
	lines = append(lines, call(7, "deploy", map[string]any{"secret": "db-password", "runner_id": testRunnerID,
		"target": map[string]any{"kind": "env-file", "path": "/etc/app/app.env", "uid": 1, "gid": 1, "value": value}}))
	out := session(t, srvr, lines...)
	if strings.Count(out, `"isError":true`) != 7 {
		t.Fatalf("a call carrying a value was not refused: %s", out)
	}
	if c.In(out) || c.In(s.all()) {
		t.Fatalf("value echoed or forwarded: out=%s", out)
	}
	if s.all() != "" {
		t.Fatalf("a refused call still reached the server: %s", s.all())
	}
}

// The token is only ever sent to the configured host.
func TestRedirectNeverCarriesToken(t *testing.T) {
	c := canary.New()
	token := c.Value(2)
	var other seen
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		other.add(r, nil)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("[]"))
	}))
	defer elsewhere.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect) //nolint:gosec // G710: a test server redirecting to another test server
	}))
	defer origin.Close()
	out := session(t, newTestServer(t, origin.URL, token), everyCall()...)
	if other.all() != "" {
		t.Fatalf("redirect was followed: %s", other.all())
	}
	if c.In(out) {
		t.Fatalf("token in answer: %s", out)
	}
}

func TestToolList(t *testing.T) {
	var s seen
	srv := restFake(t, "", &s)
	out := session(t, newTestServer(t, srv.URL, "tok"), rpc(1, "tools/list", map[string]any{}))
	for _, name := range []string{"list_secrets", "get_secret_meta", "request_secret_input", "deploy", "rotate", "verify_carriers"} {
		if !strings.Contains(out, `"name":"`+name+`"`) {
			t.Fatalf("tool %s missing: %s", name, out)
		}
	}
}

// With a well-behaved server every tool answers with exactly its closed object.
func TestToolsAnswerFromTheClosedList(t *testing.T) {
	var s seen
	srv := restFake(t, "", &s)
	out := session(t, newTestServer(t, srv.URL, "tok"), everyCall()...)
	if strings.Contains(out, `"isError":true`) {
		t.Fatalf("a well-formed reply was refused: %s", out)
	}
	for _, want := range []string{"db-password", "kfp1:k:abcdefghijklmnop", "https://keep.example/input/tok", "builtin://db-password"} {
		if !strings.Contains(out, want) {
			t.Fatalf("answer lacks %q: %s", want, out)
		}
	}
	got := s.all()
	for _, want := range []string{"GET /orgs/" + testOrg + "/secrets?scope_id=" + testOrg + "&scope_level=org", "POST /v1/input-links", "POST /v1/deployments", "POST /orgs/" + testOrg + "/secrets/" + testSecretID + "/rotate", "GET /orgs/" + testOrg + "/secrets/" + testSecretID + "/rotate/" + testRequest, "POST /v1/carriers/verify"} {
		if !strings.Contains(got, want) {
			t.Fatalf("server never saw %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, `"Authorization":["Bearer tok"]`) {
		t.Fatal("the caller's own token was not sent")
	}
}
