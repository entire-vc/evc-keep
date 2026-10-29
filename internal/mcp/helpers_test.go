package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

const (
	testSecretID = "019a0000-0000-7000-8000-000000000001"
	testRunnerID = "019a0000-0000-7000-8000-000000000002"
	testRunner2  = "019a0000-0000-7000-8000-000000000003"
	testOrg      = "019a0000-0000-7000-8000-0000000000aa"
	testRequest  = "019a0000-0000-7000-8000-0000000000bb"
)

// seen is what the fake REST server received, so a test can prove what did
// and did not cross the boundary.
type seen struct {
	mu   sync.Mutex
	reqs []string
}

func (s *seen) add(r *http.Request, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hdr, _ := json.Marshal(r.Header)
	s.reqs = append(s.reqs, r.Method+" "+r.URL.RequestURI()+" "+string(hdr)+" "+string(body))
}

func (s *seen) all() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.reqs, "\n")
}

// restFake is a Keep REST API stand-in. With hostile set, every answer
// carries extra fields holding the canary, as a server bug would.
func restFake(t *testing.T, hostile string, s *seen) *httptest.Server {
	t.Helper()
	extra := func(m map[string]any) map[string]any {
		if hostile != "" {
			m["value"] = hostile
			m["plaintext"] = hostile
			m["debug"] = map[string]any{"first_secret": hostile}
		}
		return m
	}
	reply := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		if hostile != "" {
			w.Header().Set("X-Debug", hostile)
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	secret := func() map[string]any {
		return extra(map[string]any{"id": testSecretID, "name": "db-password", "scope": "org:" + testOrg, "class": "prod", "type": "password",
			"store": extra(map[string]any{"id": "s1", "name": "builtin", "provider": "builtin"}), "provider_ref": "builtin://db-password",
			"created_at": time.Unix(1, 0).UTC(), "updated_at": time.Unix(2, 0).UTC()})
	}
	mux := http.NewServeMux()
	wrap := func(h func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc { return h }
	mux.HandleFunc("GET /orgs/{org}/secrets", wrap(func(w http.ResponseWriter, r *http.Request) { reply(w, 200, []any{secret()}) }))
	mux.HandleFunc("GET /orgs/{org}/secrets/{id}", wrap(func(w http.ResponseWriter, r *http.Request) { reply(w, 200, secret()) }))
	mux.HandleFunc("GET /orgs/{org}/secrets/{id}/versions", wrap(func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, []any{extra(map[string]any{"version": "v1", "created_at": time.Unix(1, 0).UTC(), "fingerprint": "kfp1:k:abcdefghijklmnop", "length": 12, "status": "current"})})
	}))
	mux.HandleFunc("POST /v1/input-links", wrap(func(w http.ResponseWriter, r *http.Request) {
		reply(w, 201, extra(map[string]any{"url": "https://keep.example/input/tok", "expires_at": time.Unix(3, 0).UTC(), "request_id": testRequest}))
	}))
	mux.HandleFunc("POST /v1/deployments", wrap(func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, extra(map[string]any{"ok": true, "request_id": testRequest, "fingerprint": "kfp1:k:abcdefghijklmnop", "version": "v1"}))
	}))
	mux.HandleFunc("GET /v1/deployments/{id}", wrap(func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, extra(map[string]any{"ok": true, "request_id": testRequest}))
	}))
	mux.HandleFunc("POST /orgs/{org}/secrets/{id}/rotate", wrap(func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Mode string `json:"mode"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b.Mode == "human_input" {
			reply(w, 202, extra(map[string]any{"url": "https://keep.example/input/tok", "expires_at": time.Unix(3, 0).UTC(), "request_id": testRequest}))
			return
		}
		reply(w, 202, extra(map[string]any{"ok": false, "request_id": testRequest}))
	}))
	mux.HandleFunc("GET /orgs/{org}/secrets/{id}/rotate/{rid}", wrap(func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, extra(map[string]any{"ok": true, "request_id": testRequest, "fingerprint": "kfp1:k:abcdefghijklmnop", "version": "2",
			"carriers": []any{extra(map[string]any{"carrier_id": testRunnerID, "phase": "verify", "state": "ok"})}}))
	}))
	verification := func() map[string]any {
		return extra(map[string]any{"ok": true, "request_id": testRequest, "fingerprint": "kfp1:k:abcdefghijklmnop", "version": "v1",
			"carriers": []any{extra(map[string]any{"id": testRunnerID, "host": "host-1", "runner_id": testRunner2, "target": extra(map[string]any{"kind": "env-file", "path": "/etc/app/app.env"}),
				"status": "match", "last_verified_at": time.Unix(4, 0).UTC(), "fingerprint_match": true})}})
	}
	mux.HandleFunc("POST /v1/carriers/verify", wrap(func(w http.ResponseWriter, r *http.Request) { reply(w, 200, verification()) }))
	mux.HandleFunc("GET /v1/carriers/verify/{id}", wrap(func(w http.ResponseWriter, r *http.Request) { reply(w, 200, verification()) }))
	// Recording sits outside the mux: a request that matches no route is seen too.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.add(r, b)
		r.Body = io.NopCloser(bytes.NewReader(b))
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestServer(t *testing.T, base, token string) *Server {
	t.Helper()
	s, err := New(Config{BaseURL: base, Org: testOrg, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rpc(id int, method string, params any) string {
	p, _ := json.Marshal(params)
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":%s}`, id, method, p)
}

// session feeds lines to the server and returns everything it wrote.
func session(t *testing.T, s *Server, lines ...string) string {
	t.Helper()
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := s.Serve(ctx, strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func call(id int, name string, args any) string {
	return rpc(id, "tools/call", map[string]any{"name": name, "arguments": args})
}

// everyCall exercises each tool once with valid arguments.
func everyCall() []string {
	return []string{
		call(1, "list_secrets", map[string]any{"scope_level": "org", "scope_id": testOrg}),
		call(2, "get_secret_meta", map[string]any{"secret_id": testSecretID}),
		call(3, "request_secret_input", map[string]any{"secret": "db-password"}),
		call(4, "deploy", map[string]any{"secret": "db-password", "runner_id": testRunnerID,
			"target": map[string]any{"kind": "env-file", "path": "/etc/app/app.env", "field": "DB_PASSWORD", "uid": 1000, "gid": 1000}}),
		call(5, "rotate", map[string]any{"secret_id": testSecretID, "mode": "generate", "wait_seconds": 5}),
		call(6, "verify_carriers", map[string]any{"secret": "db-password"}),
	}
}

func requireDetectorSees(t *testing.T, c canary.Canary, forms ...string) {
	t.Helper()
	for _, f := range forms {
		if !c.In(f) {
			t.Fatal("canary detector is blind; the test proves nothing")
		}
	}
}

// The poll interval is a second in production; the tests wait a few
// milliseconds. A test that needs another value sets and restores it itself.
func init() { pollEvery = 5 * time.Millisecond }
