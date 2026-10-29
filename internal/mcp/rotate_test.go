package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func rotateArgs(extra map[string]any) map[string]any {
	a := map[string]any{"secret_id": testSecretID, "mode": "generate"}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

// rotateServer answers the start with 202 and the status with body (code 200).
func rotateServer(t *testing.T, status string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"ok":false,"request_id":"` + testRequest + `"}`))
			return
		}
		polls.Add(1)
		_, _ = w.Write([]byte(status))
	}))
	t.Cleanup(srv.Close)
	return srv, &polls
}

func TestRotateReturnsThePerCarrierResult(t *testing.T) {
	srv, polls := rotateServer(t, `{"ok":true,"request_id":"`+testRequest+`","fingerprint":"kfp1:k:abcdefghijklmnop","version":"2","carriers":[{"carrier_id":"`+testRunnerID+`","phase":"verify","state":"ok"}]}`)
	got := answers(t, session(t, newTestServer(t, srv.URL, "tok"), call(1, "rotate", rotateArgs(nil))))
	if got[0].Result.IsError {
		t.Fatalf("refused: %+v", got[0])
	}
	var res RotateResult
	if err := json.Unmarshal([]byte(got[0].Result.Content[0].Text), &res); err != nil || !res.OK || res.Version != "2" || len(res.Carriers) != 1 || polls.Load() != 1 {
		t.Fatalf("result %+v err %v polls %d", res, err, polls.Load())
	}
}

// A failed run is an answer, not an error: class, stale carriers, no version.
func TestRotateFailedRunNamesClassAndNoVersion(t *testing.T) {
	srv, _ := rotateServer(t, `{"ok":false,"request_id":"`+testRequest+`","error_class":"deploy_failed","carriers":[{"carrier_id":"`+testRunnerID+`","phase":"deploy","state":"stale"}]}`)
	got := answers(t, session(t, newTestServer(t, srv.URL, "tok"), call(1, "rotate", rotateArgs(nil))))
	var res RotateResult
	if err := json.Unmarshal([]byte(got[0].Result.Content[0].Text), &res); err != nil || got[0].Result.IsError || res.OK || res.ErrorClass != "deploy_failed" || res.Version != "" || res.Carriers[0].State != "stale" {
		t.Fatalf("got %+v err %v", res, err)
	}
}

func TestRotateWaitZeroDoesNotPoll(t *testing.T) {
	srv, polls := rotateServer(t, `{}`)
	got := answers(t, session(t, newTestServer(t, srv.URL, "tok"), call(1, "rotate", rotateArgs(map[string]any{"wait_seconds": 0}))))
	var res RotateResult
	if err := json.Unmarshal([]byte(got[0].Result.Content[0].Text), &res); err != nil || res.OK || res.RequestID != testRequest || polls.Load() != 0 {
		t.Fatalf("got %+v err %v polls %d", res, err, polls.Load())
	}
}

func TestRotateHumanInputReturnsTheLinkOnly(t *testing.T) {
	var s seen
	srv := restFake(t, "", &s)
	got := answers(t, session(t, newTestServer(t, srv.URL, "tok"), call(1, "rotate", rotateArgs(map[string]any{"mode": "human_input"}))))
	var link InputLink
	if got[0].Result.IsError || json.Unmarshal([]byte(got[0].Result.Content[0].Text), &link) != nil || link.URL == "" || link.RequestID != testRequest {
		t.Fatalf("got %+v", got[0])
	}
	if strings.Count(s.all(), "\n") != 0 || !strings.Contains(s.all(), `{"mode":"human_input"}`) {
		t.Fatalf("one POST with the mode only was expected: %s", s.all())
	}
}

// No argument beyond the three, and no value: refused before the server is reached.
func TestRotateRefusesBadArgumentsBeforeTheServer(t *testing.T) {
	c := canary.New()
	value := c.Value(1)
	requireDetectorSees(t, c, "x "+value)
	var s seen
	srv := restFake(t, "", &s)
	var lines []string
	for i, args := range []map[string]any{
		rotateArgs(map[string]any{"value": value}),
		rotateArgs(map[string]any{"secret_value": value}),
		rotateArgs(map[string]any{"mode": value}),
		rotateArgs(map[string]any{"mode": "set"}),
		rotateArgs(map[string]any{"secret_id": "not-an-id"}),
		rotateArgs(map[string]any{"secret_id": "../" + value}),
		rotateArgs(map[string]any{"wait_seconds": maxWait + 1}),
		rotateArgs(map[string]any{"wait_seconds": -1}),
		{"mode": "generate"},
	} {
		lines = append(lines, call(i+1, "rotate", args))
	}
	out := session(t, newTestServer(t, srv.URL, "tok"), lines...)
	if strings.Count(out, `"isError":true`) != len(lines) {
		t.Fatalf("a bad call was not refused: %s", out)
	}
	if c.In(out) || c.In(s.all()) || s.all() != "" {
		t.Fatalf("value echoed or a refused call reached the server: out=%s", out)
	}
}

// A status that does not have the shape of its fields is refused whole, and
// the canary a hostile server puts in any text field reaches no answer.
func TestRotateRefusesAStatusOutsideTheClosedShape(t *testing.T) {
	c := canary.New()
	value := c.Value(1)
	requireDetectorSees(t, c, "x "+value)
	good := func(extra string) string {
		return `{"ok":false,"request_id":"` + testRequest + `"` + extra + `}`
	}
	done := func(extra string) string {
		return `{"ok":true,"request_id":"` + testRequest + `"` + extra + `}`
	}
	for name, body := range map[string]string{
		"extra field":           good(`,"value":"` + value + `"`),
		"free text class":       good(`,"error_class":"boom ` + value + `"`),
		"class from deploy":     good(`,"error_class":"target_write_failed"`),
		"free text version":     done(`,"fingerprint":"kfp1:k:abcdefghijklmnop","version":"` + value + `"`),
		"bad fingerprint":       done(`,"version":"2","fingerprint":"` + value + `"`),
		"carrier id is text":    good(`,"carriers":[{"carrier_id":"` + value + `","phase":"deploy","state":"ok"}]`),
		"carrier state text":    good(`,"carriers":[{"carrier_id":"` + testRunnerID + `","phase":"deploy","state":"` + value + `"}]`),
		"carrier extra field":   good(`,"carriers":[{"carrier_id":"` + testRunnerID + `","phase":"deploy","state":"ok","value":"` + value + `"}]`),
		"version before ok":     good(`,"version":"2"`),
		"fingerprint before ok": good(`,"fingerprint":"kfp1:k:abcdefghijklmnop"`),
		"class on ok":           `{"ok":true,"request_id":"` + testRequest + `","version":"2","fingerprint":"kfp1:k:abcdefghijklmnop","error_class":"deploy_failed"}`,
		"request id is text":    `{"ok":false,"request_id":"` + value + `"}`,
		"carrier phase text":    good(`,"carriers":[{"carrier_id":"` + testRunnerID + `","phase":"` + value + `","state":"ok"}]`),
		"too many carriers":     good(`,"carriers":[` + strings.TrimSuffix(strings.Repeat(`{"carrier_id":"`+testRunnerID+`","phase":"deploy","state":"ok"},`, 257), ",") + `]`),
	} {
		t.Run(name, func(t *testing.T) {
			srv, _ := rotateServer(t, body)
			out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "rotate", rotateArgs(nil)))
			if !strings.Contains(out, `"isError":true`) {
				t.Fatalf("shape was accepted (positive control): %s", out)
			}
			if c.In(out) {
				t.Fatalf("canary reached the answer: %s", out)
			}
		})
	}
}

// The status code and the body must agree: 202 is only "running", and a 200
// that says ok names the version and the fingerprint.
func TestRotateRefusesAStatusCodeThatContradictsItsBody(t *testing.T) {
	ok := `"ok":true,"request_id":"` + testRequest + `"`
	for name, tc := range map[string]struct {
		code int
		body string
	}{
		"202 says ok":                {202, `{` + ok + `,"version":"2","fingerprint":"kfp1:k:abcdefghijklmnop"}`},
		"202 says failed":            {202, `{"ok":false,"request_id":"` + testRequest + `","error_class":"deploy_failed"}`},
		"200 ok without version":     {200, `{` + ok + `,"fingerprint":"kfp1:k:abcdefghijklmnop"}`},
		"200 ok without fingerprint": {200, `{` + ok + `,"version":"2"}`},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				code := 202
				body := `{"ok":false,"request_id":"` + testRequest + `"}`
				if r.Method == http.MethodGet {
					code, body = tc.code, tc.body
				}
				w.WriteHeader(code)
				_, _ = w.Write([]byte(body))
			}))
			t.Cleanup(srv.Close)
			out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "rotate", rotateArgs(map[string]any{"wait_seconds": 1})))
			if !strings.Contains(out, `"isError":true`) {
				t.Fatalf("contradiction accepted: %s", out)
			}
		})
	}
}

// human_input is answered by a link and 202; any other status is refused.
func TestRotateHumanInputRefusesAStatusOtherThan202(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"url":"https://keep.example/i/x","expires_at":"2030-01-01T00:00:00Z","request_id":"` + testRequest + `"}`))
	}))
	t.Cleanup(srv.Close)
	out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "rotate", rotateArgs(map[string]any{"mode": "human_input"})))
	if !strings.Contains(out, `"isError":true`) {
		t.Fatalf("a 200 answer was taken for an issued link: %s", out)
	}
}

// The start is answered by 202 and the status by 200 or 202. Another 2xx, or
// a non-2xx, is refused even when its body has the right shape.
func TestRotateRefusesAnUnexpectedStatusCode(t *testing.T) {
	ok := `{"ok":false,"request_id":"` + testRequest + `"}`
	for name, codes := range map[string][2]int{
		"start 200":  {200, 200},
		"start 201":  {201, 200},
		"status 201": {202, 201},
		"status 204": {202, 204},
		"status 500": {202, 500},
		"status 404": {202, 404},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				code := codes[1]
				if r.Method == http.MethodPost {
					code = codes[0]
				}
				w.WriteHeader(code)
				if code != 204 {
					_, _ = w.Write([]byte(ok))
				}
			}))
			t.Cleanup(srv.Close)
			out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "rotate", rotateArgs(nil)))
			if !strings.Contains(out, `"isError":true`) {
				t.Fatalf("an unexpected status was accepted: %s", out)
			}
		})
	}
	// Positive control: 202 then 200 and 202 then 202 are accepted.
	for _, last := range []int{200, 202} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				w.WriteHeader(202)
			} else {
				w.WriteHeader(last)
			}
			_, _ = w.Write([]byte(ok))
		}))
		t.Cleanup(srv.Close)
		out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "rotate", rotateArgs(map[string]any{"wait_seconds": 0})))
		if strings.Contains(out, `"isError":true`) {
			t.Fatalf("a good status %d was refused: %s", last, out)
		}
	}
}
