package mcp

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

type rpcOut struct {
	ID     int `json:"id"`
	Result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	} `json:"result"`
	Error *rpcError `json:"error"`
}

func answers(t *testing.T, out string) []rpcOut {
	t.Helper()
	var all []rpcOut
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var r rpcOut
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("not JSON: %q", l)
		}
		all = append(all, r)
	}
	return all
}

func deployArgs(extra map[string]any) map[string]any {
	a := map[string]any{"secret": "db-password", "runner_id": testRunnerID,
		"target": map[string]any{"path": "/etc/app/app.env", "uid": 1000, "gid": 1000}}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

func TestDeployPollsUntilTheRunnerAnswers(t *testing.T) {
	old := pollEvery
	pollEvery = 5 * time.Millisecond
	defer func() { pollEvery = old }()
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"ok":false,"request_id":"` + testRequest + `"}`))
			return
		}
		if polls.Add(1) < 3 {
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"ok":false,"request_id":"` + testRequest + `"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"request_id":"` + testRequest + `","fingerprint":"kfp1:k:abcdefghijklmnop","version":"v2","healthcheck":{"status":"ok","checked_at":"1970-01-01T00:00:01Z"}}`))
	}))
	defer srv.Close()
	got := answers(t, session(t, newTestServer(t, srv.URL, "tok"), call(1, "deploy", deployArgs(nil))))
	text := got[0].Result.Content[0].Text
	if got[0].Result.IsError || !strings.Contains(text, `"ok":true`) || !strings.Contains(text, `"version":"v2"`) || polls.Load() != 3 {
		t.Fatalf("polls=%d answer=%s", polls.Load(), text)
	}
}

func TestDeployWaitIsBoundedAndPendingIsReported(t *testing.T) {
	old := pollEvery
	pollEvery = 5 * time.Millisecond
	defer func() { pollEvery = old }()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(202)
		_, _ = w.Write([]byte(`{"ok":false,"request_id":"` + testRequest + `"}`))
	}))
	defer srv.Close()
	started := time.Now()
	got := answers(t, session(t, newTestServer(t, srv.URL, "tok"), call(1, "deploy", deployArgs(map[string]any{"wait_seconds": 0}))))
	if calls.Load() != 1 || !strings.Contains(got[0].Result.Content[0].Text, `"ok":false`) || time.Since(started) > 2*time.Second {
		t.Fatalf("wait_seconds=0 must not poll: calls=%d", calls.Load())
	}
	out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "deploy", deployArgs(map[string]any{"wait_seconds": maxWait + 1})))
	if !strings.Contains(out, `"isError":true`) || !strings.Contains(out, "arguments are invalid") {
		t.Fatalf("an unbounded wait was accepted: %s", out)
	}
}

func TestDeployApprovalIsReturnedAtOnce(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(202)
		_, _ = w.Write([]byte(`{"ok":false,"request_id":"` + testRequest + `","approval":{"id":"a1","status":"pending","url":"https://keep.example/console/a1"}}`))
	}))
	defer srv.Close()
	got := answers(t, session(t, newTestServer(t, srv.URL, "tok"), call(1, "deploy", deployArgs(nil))))
	if calls.Load() != 1 || !strings.Contains(got[0].Result.Content[0].Text, `"approval"`) {
		t.Fatalf("calls=%d answer=%s", calls.Load(), got[0].Result.Content[0].Text)
	}
}

func TestServerErrorKeepsClassAndRequestID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error_class":"secret_not_found","message":"no secret named \"x\"\u001b[31m","request_id":"` + testRequest + `"}`))
	}))
	defer srv.Close()
	got := answers(t, session(t, newTestServer(t, srv.URL, "tok"), call(1, "get_secret_meta", map[string]any{"secret_id": testSecretID})))
	var e ErrorAnswer
	if err := json.Unmarshal([]byte(got[0].Result.Content[0].Text), &e); err != nil || !got[0].Result.IsError {
		t.Fatalf("not an error answer: %v", got[0])
	}
	if e.ErrorClass != "secret_not_found" || e.RequestID != testRequest || strings.ContainsRune(e.Message, 0x1b) {
		t.Fatalf("%+v", e)
	}
}

func TestBadArgumentsNeverReachTheServer(t *testing.T) {
	var s seen
	srv := restFake(t, "", &s)
	srvr := newTestServer(t, srv.URL, "tok")
	var lines []string
	for i, c := range []struct {
		name string
		args any
	}{
		{"list_secrets", map[string]any{"scope_level": "galaxy", "scope_id": testOrg}},
		{"list_secrets", map[string]any{"scope_level": "org", "scope_id": "../../x"}},
		{"get_secret_meta", map[string]any{"secret_id": "../versions"}},
		{"get_secret_meta", map[string]any{}},
		{"request_secret_input", map[string]any{"secret": "a\nb"}},
		{"request_secret_input", map[string]any{"secret": "x", "ttl": "48h"}},
		{"deploy", deployArgs(map[string]any{"runner_id": "nope"})},
		{"deploy", deployArgs(map[string]any{"request_id": "../x"})},
		{"deploy", map[string]any{"secret": "x", "runner_id": testRunnerID, "target": map[string]any{"path": "/p"}}},
		{"get_secret_meta", []any{1}},
	} {
		lines = append(lines, call(i+1, c.name, c.args))
	}
	out := session(t, srvr, lines...)
	if strings.Count(out, `"isError":true`) != len(lines) {
		t.Fatalf("a bad call was accepted: %s", out)
	}
	if s.all() != "" {
		t.Fatalf("a refused call reached the server: %s", s.all())
	}
}

func TestProtocolBasics(t *testing.T) {
	var s seen
	srv := restFake(t, "", &s)
	out := session(t, newTestServer(t, srv.URL, "tok"),
		rpc(1, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "t", "version": "0"}}),
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		rpc(2, "ping", map[string]any{}),
		rpc(3, "resources/list", map[string]any{}),
		rpc(4, "tools/call", map[string]any{"name": "show_value", "arguments": map[string]any{}}),
		`not json`,
	)
	got := answers(t, out)
	if len(got) != 5 {
		t.Fatalf("a notification was answered or an answer is missing: %s", out)
	}
	if !strings.Contains(strings.Split(out, "\n")[0], `"tools"`) || got[2].Error == nil || got[2].Error.Code != codeMethodNotFound ||
		got[3].Error == nil || got[3].Error.Message != "unknown tool" || got[4].Error == nil || got[4].Error.Code != codeParse {
		t.Fatalf("unexpected protocol answers: %s", out)
	}
}

func TestNewRefusesInsecureOrIncompleteConfig(t *testing.T) {
	for name, cfg := range map[string]Config{
		"http-remote":      {BaseURL: "http://keep.example", Org: testOrg, Token: "t"},
		"userinfo":         {BaseURL: "https://u:p@keep.example", Org: testOrg, Token: "t"}, //nolint:gosec // G101: the rejected input itself
		"no-token":         {BaseURL: "https://keep.example", Org: testOrg},
		"no-org":           {BaseURL: "https://keep.example", Token: "t"},
		"not-a-url":        {BaseURL: "::", Org: testOrg, Token: "t"},
		"ftp":              {BaseURL: "ftp://127.0.0.1", Org: testOrg, Token: "t"},
		"localhost-suffix": {BaseURL: "http://evillocalhost", Org: testOrg, Token: "t"},
		"localhost-prefix": {BaseURL: "http://localhost.evil.example", Org: testOrg, Token: "t"},
		"loopback-prefix":  {BaseURL: "http://127.0.0.1.evil.example", Org: testOrg, Token: "t"},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(Config{BaseURL: "http://127.0.0.1:9", Org: testOrg, Token: "t"}); err != nil {
		t.Errorf("loopback http refused: %v", err)
	}
}

// A class or request id that does not have the shape of one is replaced, not forwarded.
func TestMalformedErrorFieldsAreNotForwarded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"error_class":"Not A Class: kc-injected","message":"m","request_id":"../kc-injected"}`))
	}))
	defer srv.Close()
	out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "get_secret_meta", map[string]any{"secret_id": testSecretID}))
	var e ErrorAnswer
	if err := json.Unmarshal([]byte(answers(t, out)[0].Result.Content[0].Text), &e); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "kc-injected") || e.ErrorClass != "internal" || e.RequestID != "" {
		t.Fatalf("%+v", e)
	}
}

// A deploy answer whose strings are not of the closed shapes is refused whole.
func TestDeployAnswerWithOddStringsIsRefused(t *testing.T) {
	c := canary.New()
	value := c.Value(1)
	for name, body := range map[string]map[string]any{
		"class":       {"ok": false, "request_id": testRequest, "error_class": "x_" + strings.ToLower(value)},
		"fingerprint": {"ok": true, "request_id": testRequest, "fingerprint": value},
		"request-id":  {"ok": true, "request_id": "../" + value},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer srv.Close()
			out := session(t, newTestServer(t, srv.URL, "tok"), everyCall()[3])
			if !strings.Contains(out, `"isError":true`) || c.In(out) {
				t.Fatalf("odd answer was passed on: %s", out)
			}
		})
	}
}

// tools/call without an id is a notification: nobody can read its answer, so it is not run.
func TestCallWithoutIDIsNotRun(t *testing.T) {
	var s seen
	srv := restFake(t, "", &s)
	_ = session(t, newTestServer(t, srv.URL, "tok"), strings.Replace(everyCall()[3], `"id":4,`, "", 1), rpc(9, "ping", nil))
	if s.all() != "" {
		t.Fatalf("a call without id reached the server: %s", s.all())
	}
}

// A protocol error never echoes what the peer sent: not the method, not the
// broken line, not the params.
func TestProtocolErrorsEchoNothing(t *testing.T) {
	c := canary.New()
	value := c.Value(1)
	var s seen
	srv := restFake(t, "", &s)
	out := session(t, newTestServer(t, srv.URL, "tok"),
		rpc(1, "method/"+value, map[string]any{}),
		"not json "+value,
		rpc(2, "tools/call", map[string]any{"name": 7, "arguments": value}),
		`{"jsonrpc":"`+value+`","id":3,"method":"ping"}`,
	)
	if strings.Count(out, "\n") != 4 || !strings.Contains(out, `"error"`) {
		t.Fatalf("no protocol errors (positive control): %q", out)
	}
	if c.In(out) {
		t.Fatalf("a protocol error echoed the peer: %s", out)
	}
}

// Only 201 is a created input link.
func TestInputLinkNeedsCreated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"url":"https://keep.example/i/x","expires_at":"1970-01-01T00:00:03Z","request_id":"` + testRequest + `"}`))
	}))
	defer srv.Close()
	out := session(t, newTestServer(t, srv.URL, "tok"), everyCall()[2])
	if !strings.Contains(out, `"isError":true`) {
		t.Fatalf("a 200 was taken for a created link: %s", out)
	}
}

// A request id is peer-controlled text that the server would copy to stdout.
// Only a plain integer is echoed; any other id (string, object, array, float,
// null) is refused with a null id, so no peer-supplied value rides back.
func TestRequestIDIsNeverReflectedUnlessInteger(t *testing.T) {
	c := canary.New()
	value := c.Value(1)
	if !c.In(`"`+value+`"`) || !c.In(hex.EncodeToString([]byte(value))) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	var s seen
	srv := restFake(t, "", &s)
	hostile := []string{
		`"` + value + `"`,
		`{"k":"` + value + `"}`,
		`["` + value + `"]`,
		`1.5`, `1e3`, `null`, `true`, `12345678901234567890`, `-0`, `01`,
	}
	for i, id := range hostile {
		for _, method := range []string{"ping", "no/such", "tools/call"} {
			line := `{"jsonrpc":"2.0","id":` + id + `,"method":"` + method + `","params":{"name":7}}`
			out := session(t, newTestServer(t, srv.URL, "tok"), line)
			if strings.Count(out, "\n") != 1 || !strings.Contains(out, `"id":null`) || !strings.Contains(out, `"error"`) || strings.Contains(out, `"result"`) {
				t.Fatalf("hostile id #%d on %s: not a null-id refusal", i, method)
			}
			if c.In(out) {
				t.Fatalf("hostile id #%d on %s reflected the peer's value", i, method)
			}
		}
	}
	for _, id := range []string{"0", "1", "-7", "9007199254740991"} {
		out := session(t, newTestServer(t, srv.URL, "tok"), `{"jsonrpc":"2.0","id":`+id+`,"method":"ping"}`)
		if !strings.Contains(out, `"id":`+id+`,`) && !strings.Contains(out, `"id":`+id+`}`) || !strings.Contains(out, `"result"`) {
			t.Fatalf("integer id %s was not echoed on a good call", id)
		}
	}
}

const carrierRow = `{"id":"` + testRunnerID + `","host":"h1","target":{"kind":"env-file","path":"/etc/app/app.env"},"status":"STATUS"`

func TestVerifyCarriersPollsUntilTheRunnersAnswer(t *testing.T) {
	old := pollEvery
	pollEvery = 5 * time.Millisecond
	defer func() { pollEvery = old }()
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pending := r.Method == "POST" || polls.Add(1) < 3
		if pending {
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"ok":false,"request_id":"` + testRequest + `","carriers":[` + strings.Replace(carrierRow, "STATUS", "pending", 1) + `}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":false,"request_id":"` + testRequest + `","fingerprint":"kfp1:k:abcdefghijklmnop","version":"v2","carriers":[` +
			strings.Replace(carrierRow, "STATUS", "mismatch", 1) + `,"fingerprint_match":false,"error_class":"fingerprint_mismatch"}]}`))
	}))
	defer srv.Close()
	got := answers(t, session(t, newTestServer(t, srv.URL, "tok"), call(1, "verify_carriers", map[string]any{"secret": "db-password"})))
	text := got[0].Result.Content[0].Text
	if got[0].Result.IsError || !strings.Contains(text, `"status":"mismatch"`) || !strings.Contains(text, `"error_class":"fingerprint_mismatch"`) || polls.Load() != 3 {
		t.Fatalf("polls=%d answer=%s", polls.Load(), text)
	}
}

func TestVerifyCarriersWaitIsBoundedAndHostileRepliesAreRefused(t *testing.T) {
	old := pollEvery
	pollEvery = 5 * time.Millisecond
	defer func() { pollEvery = old }()
	var calls atomic.Int32
	reply := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(202)
		_, _ = w.Write([]byte(reply))
	}))
	defer srv.Close()
	reply = `{"ok":false,"request_id":"` + testRequest + `","carriers":[` + strings.Replace(carrierRow, "STATUS", "pending", 1) + `}]}`
	got := answers(t, session(t, newTestServer(t, srv.URL, "tok"), call(1, "verify_carriers", map[string]any{"secret": "db-password", "wait_seconds": 0})))
	if calls.Load() != 1 || !strings.Contains(got[0].Result.Content[0].Text, `"status":"pending"`) {
		t.Fatalf("wait_seconds=0 must not poll: calls=%d", calls.Load())
	}
	out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "verify_carriers", map[string]any{"secret": "db-password", "wait_seconds": maxWait + 1}))
	if !strings.Contains(out, "arguments are invalid") {
		t.Fatalf("an unbounded wait was accepted: %s", out)
	}
	for name, bad := range map[string]string{
		"extra-field":     `{"ok":true,"request_id":"` + testRequest + `","value":"x","carriers":[]}`,
		"trailing-value":  `{"ok":true,"request_id":"` + testRequest + `","carriers":[]}{"value":"x"}`,
		"trailing-brace":  `{"ok":true,"request_id":"` + testRequest + `","carriers":[]}}`,
		"unknown-status":  `{"ok":true,"request_id":"` + testRequest + `","carriers":[` + strings.Replace(carrierRow, "STATUS", "great", 1) + `}]}`,
		"free-class":      `{"ok":true,"request_id":"` + testRequest + `","carriers":[` + strings.Replace(carrierRow, "STATUS", "failed", 1) + `,"error_class":"hunter2"}]}`,
		"extra-in-row":    `{"ok":true,"request_id":"` + testRequest + `","carriers":[` + strings.Replace(carrierRow, "STATUS", "match", 1) + `,"value":"x"}]}`,
		"bad-fingerprint": `{"ok":true,"request_id":"` + testRequest + `","fingerprint":"hunter2","carriers":[]}`,
		"bad-request-id":  `{"ok":true,"request_id":"../hunter2 x","carriers":[]}`,
		"bad-row-id":      `{"ok":true,"request_id":"` + testRequest + `","carriers":[` + strings.Replace(strings.Replace(carrierRow, "STATUS", "match", 1), testRunnerID, "hunter2", 1) + `}]}`,
		"too-many-rows":   `{"ok":true,"request_id":"` + testRequest + `","carriers":[` + strings.TrimSuffix(strings.Repeat(strings.Replace(carrierRow, "STATUS", "match", 1)+"},", maxCarrierRows+1), ",") + `]}`,
		"bad-version":     `{"ok":true,"request_id":"` + testRequest + `","version":"` + strings.Repeat("v", 200) + `","carriers":[]}`,
		"bad-host":        `{"ok":true,"request_id":"` + testRequest + `","carriers":[` + strings.Replace(strings.Replace(carrierRow, "STATUS", "match", 1), `"host":"h1"`, `"host":"bad\u0000host"`, 1) + `}]}`,
		"bad-path":        `{"ok":true,"request_id":"` + testRequest + `","carriers":[` + strings.Replace(strings.Replace(carrierRow, "STATUS", "match", 1), `"path":"/etc/app/app.env"`, `"path":""`, 1) + `}]}`,
		"bad-kind":        `{"ok":true,"request_id":"` + testRequest + `","carriers":[` + strings.Replace(strings.Replace(carrierRow, "STATUS", "match", 1), `"kind":"env-file"`, `"kind":""`, 1) + `}]}`,
		"bad-runner-id":   `{"ok":true,"request_id":"` + testRequest + `","carriers":[` + strings.Replace(carrierRow, "STATUS", "match", 1) + `,"runner_id":"hunter2"}]}`,
		"no-carriers":     `{"ok":true,"request_id":"` + testRequest + `"}`,
	} {
		reply = bad
		out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "verify_carriers", map[string]any{"secret": "db-password"}))
		if !strings.Contains(out, "unexpected shape") || strings.Contains(out, "hunter2") {
			t.Fatalf("%s: hostile reply passed: %s", name, out)
		}
	}
}
