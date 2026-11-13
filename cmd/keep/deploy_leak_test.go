package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// hostileIDs are request ids a misbehaving server could send: each one is a
// way to push bytes into the terminal or into the poll URL.
func hostileIDs(c canary.Canary) map[string]string {
	return map[string]string{
		"canary":    c.Value(1) + "_x",
		"esc":       "req\x1b[31m-1",
		"osc":       "req\x1b]0;pwn\x07-1",
		"long":      strings.Repeat("a", 37),
		"traversal": "../v1/secrets",
		"query":     "req-1?x=1",
		"empty-seg": "req/1",
	}
}

func runDeployRaw(t *testing.T, post, get string, postStatus int, asJSON bool) (int, string, string, int32, []string) {
	return runDeployRawGet(t, post, get, postStatus, 200, asJSON)
}

func runDeployRawGet(t *testing.T, post, get string, postStatus, getStatus int, asJSON bool) (code int, out, errout string, gets int32, paths []string) {
	t.Helper()
	deployPollEvery = 5 * time.Millisecond
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			w.WriteHeader(postStatus)
			_, _ = w.Write([]byte(post))
			return
		}
		n.Add(1)
		w.WriteHeader(getStatus)
		paths = append(paths, r.URL.RequestURI())
		_, _ = w.Write([]byte(get))
	}))
	t.Cleanup(srv.Close)
	args := append([]string{}, deployArgs...)
	if asJSON {
		args = append(args, "--json")
	}
	var o, e bytes.Buffer
	code = run(args, nil, &o, &e, deployEnv(srv.URL))
	return code, o.String(), e.String(), n.Load(), paths
}

func jsonQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20:
			b.WriteString(`\u00`)
			b.WriteString(string("0123456789abcdef"[r>>4]))
			b.WriteString(string("0123456789abcdef"[r&15]))
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func cleanStream(s string) bool {
	return !strings.ContainsAny(s, "\x1b\x07") && !strings.Contains(s, "\\u001b") && !strings.Contains(s, "\\u0007")
}

// TestDeployCLIResponseFieldsNoLeak: request_id and error_class of any answer
// (200 and 202, text and JSON) are shown only in their closed shape.
func TestDeployCLIResponseFieldsNoLeak(t *testing.T) {
	c := canary.New()
	for name, id := range hostileIDs(c) {
		for _, status := range []int{200, 202} {
			for _, asJSON := range []bool{false, true} {
				body := `{"ok":false,"request_id":` + jsonQuote(id) + `}`
				code, out, errout, gets, _ := runDeployRaw(t, body, body, status, asJSON)
				all := out + errout
				if c.In(all) || !cleanStream(all) || strings.Contains(all, "../") || strings.Contains(all, "req/1") || strings.Contains(all, "x=1") || strings.Contains(all, strings.Repeat("a", 37)) {
					t.Fatalf("%s status=%d json=%v: leaked: code=%d out=%q err=%q", name, status, asJSON, code, out, errout)
				}
				if !strings.Contains(all, unexpectedValue) {
					t.Fatalf("%s status=%d json=%v: no placeholder: out=%q err=%q", name, status, asJSON, out, errout)
				}
				if strings.Contains(errout, "waiting for request") {
					t.Fatalf("%s status=%d json=%v: announced a wait it will not do: %q", name, status, asJSON, errout)
				}
				if gets != 0 {
					t.Fatalf("%s status=%d json=%v: polled with an invalid id (%d GETs)", name, status, asJSON, gets)
				}
			}
		}
	}
	// error_class: unknown → placeholder, empty stays empty, known kept.
	for _, asJSON := range []bool{false, true} {
		for _, bad := range []string{c.Value(2), "esc\x1b[2J", "NOT_A_CLASS"} {
			body := `{"ok":false,"request_id":"req-1","error_class":` + jsonQuote(bad) + `}`
			_, out, errout, _, _ := runDeployRaw(t, body, body, 200, asJSON)
			if c.In(out+errout) || !cleanStream(out+errout) || strings.Contains(out, "NOT_A_CLASS") || !strings.Contains(out, unexpectedValue) {
				t.Fatalf("json=%v class %q: out=%q err=%q", asJSON, bad, out, errout)
			}
		}
		// Altered known classes are refused: exact match only.
		for _, bad := range []string{"Policy_Denied", " policy_denied", "policy_denied ", "policy_denied_x", "policy", "internal\n"} {
			body := `{"ok":false,"request_id":"req-1","error_class":` + jsonQuote(bad) + `}`
			_, out, errout, _, _ := runDeployRaw(t, body, body, 200, asJSON)
			if !strings.Contains(out, unexpectedValue) || !cleanStream(out+errout) {
				t.Fatalf("json=%v altered class %q accepted: %q", asJSON, bad, out)
			}
		}
		// positive controls: both sets, in a 200 answer and in a polled answer.
		for _, class := range []string{"permission_denied", "policy_denied", "target_write_failed", "internal"} {
			body := `{"ok":false,"request_id":"req-1","error_class":"` + class + `"}`
			_, out, _, _, _ := runDeployRaw(t, body, body, 200, asJSON)
			if !strings.Contains(out, class) || !strings.Contains(out, "req-1") || strings.Contains(out, unexpectedValue) {
				t.Fatalf("json=%v class %s: valid fields lost: %q", asJSON, class, out)
			}
			_, out, _, gets, _ := runDeployRaw(t, `{"ok":false,"request_id":"req-1"}`, body, 202, asJSON)
			if gets < 1 || !strings.Contains(out, class) || strings.Contains(out, unexpectedValue) {
				t.Fatalf("json=%v polled class %s: %q (gets=%d)", asJSON, class, out, gets)
			}
		}
		body := `{"ok":true,"request_id":"req-1"}`
		_, out, _, _, _ := runDeployRaw(t, body, body, 200, asJSON)
		if strings.Contains(out, "error_class") || strings.Contains(out, unexpectedValue) {
			t.Fatalf("json=%v: empty class must stay empty: %q", asJSON, out)
		}
	}
}

// TestDeployCLIPollRequestIDGuard: a valid 202 id is polled (positive control);
// an invalid id in a later GET answer is never printed and stops the wait.
func TestDeployCLIPollRequestIDGuard(t *testing.T) {
	c := canary.New()
	pending := `{"ok":false,"request_id":"req-1"}`
	for _, asJSON := range []bool{false, true} {
		code, out, errout, gets, paths := runDeployRaw(t, pending, `{"ok":true,"request_id":"req-1"}`, 202, asJSON)
		if code != 0 || gets < 1 || len(paths) == 0 || paths[0] != "/v1/deployments/req-1" || !strings.Contains(out, "req-1") || !strings.Contains(errout, "waiting for request req-1") {
			t.Fatalf("json=%v control: code=%d gets=%d paths=%v out=%q err=%q", asJSON, code, gets, paths, out, errout)
		}
		for name, id := range hostileIDs(c) {
			get := `{"ok":false,"request_id":` + jsonQuote(id) + `}`
			// 202 keeps the wait alive: only the id guard can stop it.
			_, out, errout, gets, paths := runDeployRawGet(t, pending, get, 202, 202, asJSON)
			all := out + errout
			if c.In(all) || !cleanStream(all) || strings.Contains(all, "../") || strings.Contains(all, "x=1") || strings.Contains(all, strings.Repeat("a", 37)) || !strings.Contains(all, unexpectedValue) {
				t.Fatalf("%s json=%v: GET answer leaked: out=%q err=%q", name, asJSON, out, errout)
			}
			if gets != 1 {
				t.Fatalf("%s json=%v: wait did not stop after an invalid id (%d GETs, %v)", name, asJSON, gets, paths)
			}
		}
	}
}
