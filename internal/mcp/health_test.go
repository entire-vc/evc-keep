package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// healthBody is a deploy answer carrying the given healthcheck status.
func healthBody(status string) map[string]any {
	return map[string]any{"ok": true, "request_id": testRequest, "fingerprint": "kfp1:k:abcdefghijklmnop", "version": "2",
		"healthcheck": map[string]any{"status": status, "checked_at": "1970-01-01T00:00:01Z"}}
}

// healthFake answers the initial POST and the polling GET; the body under test
// is served by the one named in onPoll (true: pending POST, then GET).
func healthFake(t *testing.T, body map[string]any, onPoll bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if onPoll && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "request_id": testRequest})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// healthcheck.status is a closed list (ok/failed/skipped): any other string,
// from a server that is wrong or hostile, is refused whole, never echoed.
func TestDeployHealthStatusNoLeak(t *testing.T) {
	c := canary.New()
	value := c.Value(1)
	requireDetectorSees(t, c, "x "+value)
	for name, status := range map[string]string{
		"canary":         value,
		"canary-prefix":  "ok " + value,
		"canary-control": "ok\n\x1b[31m" + value + "\r\x00",
		"unknown":        "degraded",
		"empty":          "",
		"case":           "OK",
		"padded":         "ok ",
	} {
		for _, onPoll := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/post", true: "/poll"}[onPoll], func(t *testing.T) {
				srv := healthFake(t, healthBody(status), onPoll)
				out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "deploy", deployArgs(nil)))
				if !strings.Contains(out, `"isError":true`) || !strings.Contains(out, "unexpected shape") {
					t.Fatalf("invalid status was not refused (positive control): %s", out)
				}
				if strings.Contains(out, `\"ok\":true`) || strings.Contains(out, `"ok":true`) {
					t.Fatalf("invalid response produced ok:true: %s", out)
				}
				if c.In(out) || strings.Contains(out, "degraded") || strings.Contains(out, "\x1b") {
					t.Fatalf("health status reached the tool answer: %s", out)
				}
			})
		}
	}
}

// The closed values and an absent healthcheck keep deploy working.
func TestDeployHealthStatusClosedListWorks(t *testing.T) {
	for _, status := range []string{"ok", "failed", "skipped"} {
		srv := healthFake(t, healthBody(status), true)
		out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "deploy", deployArgs(nil)))
		if strings.Contains(out, `"isError":true`) || !strings.Contains(out, `\"status\":\"`+status+`\"`) {
			t.Fatalf("%s: deploy refused or status lost: %s", status, out)
		}
	}
	body := healthBody("ok")
	delete(body, "healthcheck")
	srv := healthFake(t, body, false)
	out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "deploy", deployArgs(nil)))
	if strings.Contains(out, `"isError":true`) || !strings.Contains(out, `\"ok\":true`) {
		t.Fatalf("deploy without healthcheck refused: %s", out)
	}
}
