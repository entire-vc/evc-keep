package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// runDeployHealth runs `keep deploy` against a server whose POST (and, for 202,
// polling GET) answer carries the given raw healthcheck object.
func runDeployHealth(t *testing.T, health string, poll, asJSON, debug bool) (code int, out, errout string) {
	t.Helper()
	prev := deployPollEvery
	deployPollEvery = 5 * time.Millisecond
	t.Cleanup(func() { deployPollEvery = prev })
	answer := func(ok bool) string {
		hc := ""
		if health != "" {
			hc = `,"healthcheck":` + health
		}
		if ok {
			return `{"ok":true,"request_id":"req-1"` + hc + `}`
		}
		return `{"ok":false,"request_id":"req-1"}`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case poll && r.Method == http.MethodPost:
			w.WriteHeader(202)
			_, _ = w.Write([]byte(answer(false)))
		default:
			_, _ = w.Write([]byte(answer(true)))
		}
	}))
	t.Cleanup(srv.Close)
	args := append([]string{}, deployArgs...)
	if asJSON {
		args = append(args, "--json")
	}
	if debug {
		args = append(args, "--debug")
	}
	var o, e bytes.Buffer
	code = run(args, nil, &o, &e, deployEnv(srv.URL))
	return code, o.String(), e.String()
}

func healthObj(statusJSON string) string {
	return `{"status":` + statusJSON + `,"checked_at":"2026-10-09T12:00:00Z"}`
}

// TestDeployHealthStatusNoLeak: healthcheck.status is a closed list
// (ok/failed/skipped); anything else in a POST or polled answer is refused with
// a static error and nothing from the answer is printed.
func TestDeployHealthStatusNoLeak(t *testing.T) {
	c := canary.New()
	long := c.Value(1) + strings.Repeat("x", 52-len(c.Value(1)))
	if len(long) < 52 || !c.In(long) {
		t.Fatalf("detector positive control failed: %d %v", len(long), c.In(long))
	}
	bad := map[string]string{
		"canary":      jsonQuote(long),
		"canary-ok":   jsonQuote("ok " + c.Value(2)),
		"empty":       `""`,
		"esc":         jsonQuote("ok\x1b[2J"),
		"osc":         jsonQuote("ok\x1b]0;pwn\x07"),
		"newline":     jsonQuote("ok\nerror_class:\tx"),
		"nul":         jsonQuote("ok\x00"),
		"upper":       `"OK"`,
		"padded":      `" ok"`,
		"prefix":      `"okay"`,
		"unknown":     `"degraded"`,
		"non-string":  `5`,
		"null":        `null`,
		"canary-both": jsonQuote(c.Value(3)),
	}
	for name, st := range bad {
		for _, poll := range []bool{false, true} {
			for _, asJSON := range []bool{false, true} {
				for _, debug := range []bool{false, true} {
					code, out, errout := runDeployHealth(t, healthObj(st), poll, asJSON, debug)
					all := out + errout
					leaked := c.In(all)
					if code == 0 || out != "" || strings.Contains(all, "ok:") || leaked || !cleanStream(all) ||
						strings.Contains(all, "degraded") || strings.Contains(all, "healthcheck") {
						// Never print the streams: with a canary input they would carry it.
						t.Fatalf("%s poll=%v json=%v debug=%v: accepted or leaked: code=%d out_len=%d err_len=%d canary_seen=%v",
							name, poll, asJSON, debug, code, len(out), len(errout), leaked)
					}
				}
			}
		}
	}
	// A healthcheck object without a status is as unknown as an empty one.
	for _, hc := range []string{`{"checked_at":"2026-10-09T12:00:00Z"}`, `{}`} {
		if code, out, _ := runDeployHealth(t, hc, false, false, false); code == 0 || out != "" {
			t.Fatalf("healthcheck %s without status accepted: code=%d out=%q", hc, code, out)
		}
	}
	// Valid statuses and an absent healthcheck keep their result and exit code.
	for _, st := range []string{"ok", "failed", "skipped"} {
		for _, poll := range []bool{false, true} {
			for _, asJSON := range []bool{false, true} {
				code, out, _ := runDeployHealth(t, healthObj(`"`+st+`"`), poll, asJSON, false)
				if code != 0 || !strings.Contains(out, st) || !strings.Contains(out, "req-1") {
					t.Fatalf("status %s poll=%v json=%v: code=%d out=%q", st, poll, asJSON, code, out)
				}
			}
		}
	}
	for _, poll := range []bool{false, true} {
		for _, asJSON := range []bool{false, true} {
			code, out, _ := runDeployHealth(t, "", poll, asJSON, false)
			if code != 0 || !strings.Contains(out, "req-1") || strings.Contains(out, "healthcheck") {
				t.Fatalf("no healthcheck poll=%v json=%v: code=%d out=%q", poll, asJSON, code, out)
			}
		}
	}
}
