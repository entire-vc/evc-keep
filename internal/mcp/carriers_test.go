package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func carrierArgs() map[string]any {
	return map[string]any{"secret_id": testSecretID, "version": "v1", "host": "web-1.example", "target_kind": "env-file",
		"target_path": "/etc/app/app.env", "target_field": "DB_PASSWORD", "consumer": "systemd:app"}
}

// carrierServer answers the register route; extra is merged into the row, as
// a server bug would.
func carrierServer(t *testing.T, s *seen, extra map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 1<<16)
		n, _ := r.Body.Read(b)
		s.add(r, b[:n])
		row := map[string]any{"id": testRunnerID, "secret_id": testSecretID, "host": "web-1.example",
			"target": map[string]any{"kind": "env-file", "path": "/etc/app/app.env"}, "consumer": "systemd:app",
			"healthcheck": "app-ready", "runner_id": testRunnerID, "status": "registered", "fingerprint_match": true}
		for k, v := range extra {
			row[k] = v
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(row)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRegisterCarrierAnswersTheClosedRow(t *testing.T) {
	var s seen
	srv := carrierServer(t, &s, nil)
	srvr := newTestServer(t, srv.URL, "tok")
	listed := session(t, srvr, rpc(1, "tools/list", map[string]any{}))
	if !strings.Contains(listed, `"name":"register_carrier"`) {
		t.Fatalf("register_carrier is not offered: %s", listed)
	}
	out := session(t, srvr, call(1, "register_carrier", carrierArgs()))
	if strings.Contains(out, `"isError":true`) || !strings.Contains(out, "web-1.example") || !strings.Contains(out, `\"status\":\"registered\"`) {
		t.Fatalf("a well-formed reply was not passed on: %s", out)
	}
	got := s.all()
	if !strings.Contains(got, "POST /orgs/"+testOrg+"/secrets/"+testSecretID+"/carriers") ||
		!strings.Contains(got, `"Authorization":["Bearer tok"]`) || !strings.Contains(got, `"target_path":"/etc/app/app.env"`) {
		t.Fatalf("request not as expected:\n%s", got)
	}
}

// The REST row carries runner_id once a runner is bound; the same reply the
// REST layer sends must come through the tool unchanged.
func TestRegisterCarrierPassesOnTheRunnerID(t *testing.T) {
	var s seen
	srv := carrierServer(t, &s, nil)
	out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "register_carrier", carrierArgs()))
	if strings.Contains(out, `"isError":true`) || !strings.Contains(out, `\"runner_id\":\"`+testRunnerID+`\"`) {
		t.Fatalf("a valid REST reply with runner_id was refused or cut: %s", out)
	}
	for name, bad := range map[string]string{"not-uuid": "nope", "short": "00000000-0000-0000-0000-00000000000", "nil-uuid": "00000000-0000-0000-0000-000000000000",
		"bare-hex": "00112233445566778899aabbccddeeff", "urn": "urn:uuid:" + testRunnerID, "braces": "{" + testRunnerID + "}", "upper": strings.ToUpper(testRunnerID)} {
		t.Run(name, func(t *testing.T) {
			var s2 seen
			srv2 := carrierServer(t, &s2, map[string]any{"runner_id": bad})
			o := session(t, newTestServer(t, srv2.URL, "tok"), call(1, "register_carrier", carrierArgs()))
			if !strings.Contains(o, `"isError":true`) || !strings.Contains(o, "unexpected shape") || strings.Contains(o, bad) {
				t.Fatalf("invalid runner_id not refused without echo: %s", o)
			}
		})
	}
}

func TestRegisterCarrierRefusesAValueAndUnknownArguments(t *testing.T) {
	c := canary.New()
	value := c.Value(1)
	requireDetectorSees(t, c, "x "+value)
	var s seen
	srv := carrierServer(t, &s, nil)
	srvr := newTestServer(t, srv.URL, "tok")
	var lines []string
	for i, k := range []string{"value", "plaintext", "fingerprint", "last_fp", "secret_value", "runner_id", "state", "healthcheck_ref"} {
		a := carrierArgs()
		a[k] = value
		lines = append(lines, call(i+1, "register_carrier", a))
	}
	bad := map[string]map[string]any{
		"no-secret":    {"version": "v1", "host": "h", "target_kind": "env-file", "target_path": "/p"},
		"bad-uuid":     {"secret_id": "nope", "version": "v1", "host": "h", "target_kind": "env-file", "target_path": "/p"},
		"no-host":      {"secret_id": testSecretID, "version": "v1", "target_kind": "env-file", "target_path": "/p"},
		"control":      {"secret_id": testSecretID, "version": "v1", "host": "h\n", "target_kind": "env-file", "target_path": "/p"},
		"no-version":   {"secret_id": testSecretID, "host": "h", "target_kind": "env-file", "target_path": "/p"},
		"no-kind":      {"secret_id": testSecretID, "version": "v1", "host": "h", "target_path": "/p"},
		"no-path":      {"secret_id": testSecretID, "version": "v1", "host": "h", "target_kind": "env-file"},
		"path-ctl":     {"secret_id": testSecretID, "version": "v1", "host": "h", "target_kind": "env-file", "target_path": "/p\n"},
		"path-long":    {"secret_id": testSecretID, "version": "v1", "host": "h", "target_kind": "env-file", "target_path": "/" + strings.Repeat("a", 4100)},
		"kind-long":    {"secret_id": testSecretID, "version": "v1", "host": "h", "target_kind": strings.Repeat("k", 40), "target_path": "/p"},
		"version-ctl":  {"secret_id": testSecretID, "version": "v\t1", "host": "h", "target_kind": "env-file", "target_path": "/p"},
		"field-ctl":    {"secret_id": testSecretID, "version": "v1", "host": "h", "target_kind": "env-file", "target_path": "/p", "target_field": "F\n"},
		"consumer-ctl": {"secret_id": testSecretID, "version": "v1", "host": "h", "target_kind": "env-file", "target_path": "/p", "consumer": "c\n"},
	}
	n := len(lines)
	for _, a := range bad {
		n++
		lines = append(lines, call(n, "register_carrier", a))
	}
	out := session(t, srvr, lines...)
	if strings.Count(out, `"isError":true`) != n {
		t.Fatalf("a bad call was not refused: %s", out)
	}
	if c.In(out) || c.In(s.all()) || s.all() != "" {
		t.Fatalf("a refused call reached the server or echoed input: out=%s seen=%s", out, s.all())
	}
}

func TestRegisterCarrierRefusesAHostileReply(t *testing.T) {
	c := canary.New()
	value := c.Value(1)
	for name, extra := range map[string]map[string]any{
		"value":       {"value": value},
		"fingerprint": {"fingerprint": value},
		"nested":      {"target": map[string]any{"kind": "env-file", "path": "/p", "value": value}},
		"runner":      {"runner_id": value},
	} {
		t.Run(name, func(t *testing.T) {
			var s seen
			srv := carrierServer(t, &s, extra)
			out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "register_carrier", carrierArgs()))
			if !strings.Contains(out, `"isError":true`) || !strings.Contains(out, "unexpected shape") {
				t.Fatalf("hostile reply not refused (positive control): %s", out)
			}
			if c.In(out) {
				t.Fatalf("canary in answer: %s", out)
			}
		})
	}
}

// A row about another secret, or a reply with the wrong status, is not what
// was asked for and is not passed on.
func TestRegisterCarrierRefusesAnAnswerAboutSomethingElse(t *testing.T) {
	var s seen
	srv := carrierServer(t, &s, map[string]any{"secret_id": testRunnerID})
	out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "register_carrier", carrierArgs()))
	if !strings.Contains(out, `"isError":true`) || strings.Contains(out, "registered") {
		t.Fatalf("a row about another secret was passed on: %s", out)
	}
	for _, code := range []int{200, 202} {
		bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"id":"` + testRunnerID + `","secret_id":"` + testSecretID + `","host":"h","target":{"kind":"env-file","path":"/p"},"status":"registered","fingerprint_match":false}`))
		}))
		out := session(t, newTestServer(t, bad.URL, "tok"), call(1, "register_carrier", carrierArgs()))
		bad.Close()
		if !strings.Contains(out, `"isError":true`) {
			t.Fatalf("status %d accepted as a registration: %s", code, out)
		}
	}
}

// An answer without an id or a status is not a registration.
func TestRegisterCarrierRefusesAnIncompleteRow(t *testing.T) {
	row := func(id, status string) string {
		return `{"id":"` + id + `","secret_id":"` + testSecretID + `","host":"h","target":{"kind":"env-file","path":"/p"},"status":"` + status + `","fingerprint_match":false}`
	}
	for name, body := range map[string]string{"id": row("", "registered"), "status": row(testRunnerID, "")} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(201)
			_, _ = w.Write([]byte(body))
		}))
		out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "register_carrier", carrierArgs()))
		srv.Close()
		if !strings.Contains(out, `"isError":true`) {
			t.Fatalf("row without %s accepted: %s", name, out)
		}
	}
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_, _ = w.Write([]byte(row(testRunnerID, "registered")))
	}))
	defer good.Close()
	if out := session(t, newTestServer(t, good.URL, "tok"), call(1, "register_carrier", carrierArgs())); strings.Contains(out, `"isError":true`) {
		t.Fatalf("positive control refused: %s", out)
	}
}

func TestRegisterCarrierRefusalsNameClassOnly(t *testing.T) {
	c := canary.New()
	host, path := c.Value(1), c.Value(2)
	for class, code := range map[string]int{"metadata_not_approved": 403, "deployment_not_confirmed": 409, "not_found": 404} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]any{"error_class": class, "message": "no " + host + " " + path, "request_id": testRequest})
		}))
		a := carrierArgs()
		a["host"], a["target_path"] = host, "/"+path
		out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "register_carrier", a))
		srv.Close()
		if !strings.Contains(out, `"isError":true`) || !strings.Contains(out, class) {
			t.Fatalf("%s: class not passed on: %s", class, out)
		}
		if c.In(out) {
			t.Fatalf("%s: host or path echoed: %s", class, out)
		}
	}
}

// Every argument reaches the REST route as given, the host included: the
// server decides on the destination, the tool does not rewrite it.
func TestRegisterCarrierPassesEveryArgumentOn(t *testing.T) {
	var s seen
	srv := carrierServer(t, &s, nil)
	srvr := newTestServer(t, srv.URL, "tok")
	_ = session(t, srvr, call(1, "register_carrier", carrierArgs()))
	got := s.all()
	for _, want := range []string{`"host":"web-1.example"`, `"version":"v1"`, `"target_kind":"env-file"`, `"target_path":"/etc/app/app.env"`,
		`"target_field":"DB_PASSWORD"`, `"consumer":"systemd:app"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("%s did not reach the server:\n%s", want, got)
		}
	}
}

// The tool's schema names exactly the required arguments; a looser list lets
// a client send a call the server will refuse.
func TestRegisterCarrierSchemaRequiresTheDestination(t *testing.T) {
	var s seen
	srv := carrierServer(t, &s, nil)
	out := session(t, newTestServer(t, srv.URL, "tok"), rpc(1, "tools/list", map[string]any{}))
	i := strings.Index(out, `"name":"register_carrier"`)
	if i < 0 {
		t.Fatalf("register_carrier is not offered: %s", out)
	}
	rest := out[i:]
	k := strings.Index(rest, `"required":[`)
	if k < 0 {
		t.Fatalf("register_carrier has no required list: %s", rest)
	}
	end := strings.Index(rest[k:], "]")
	if got, want := rest[k:k+end+1], `"required":["secret_id","version","host","target_kind","target_path"]`; got != want {
		t.Fatalf("required arguments: %s, want %s", got, want)
	}
}
