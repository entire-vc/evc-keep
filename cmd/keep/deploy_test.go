package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func deployEnv(url string) func(string) string {
	return func(k string) string {
		switch k {
		case "KEEP_SERVER":
			return url
		case "KEEP_ORG":
			return "test-org"
		case "KEEP_TOKEN":
			return "test-credential"
		}
		return ""
	}
}

var deployArgs = []string{"deploy", "db-password", "--runner", "r-1", "--target", "/srv/app/.env", "--field", "DB_PASSWORD", "--uid", "1001", "--gid", "1001", "--wait", "5s"}

func deployServer(t *testing.T, post, get func(w http.ResponseWriter), seen *map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/deployments":
			if seen != nil {
				_ = json.NewDecoder(r.Body).Decode(seen)
			}
			post(w)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/deployments/req-1":
			get(w)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDeployCLIWaitsAndPrintsOnlyTheClosedResult(t *testing.T) {
	deployPollEvery = 10 * time.Millisecond
	var seen map[string]any
	var polls atomic.Int32
	srv := deployServer(t,
		func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"ok":false,"request_id":"req-1"}`))
		},
		func(w http.ResponseWriter) {
			if polls.Add(1) < 3 {
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(`{"ok":false,"request_id":"req-1"}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"request_id":"req-1","fingerprint":"kfp1:k1:abcdefghijklmnop","version":"7","healthcheck":{"status":"ok","checked_at":"2026-10-09T12:00:00Z"}}`))
		}, &seen)
	var out, errout bytes.Buffer
	if code := run(append(append([]string{}, deployArgs...), "--debug"), nil, &out, &errout, deployEnv(srv.URL)); code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errout.String())
	}
	for _, want := range []string{"ok:", "true", "fingerprint:", "kfp1:k1:abcdefghijklmnop", "version:", "7", "healthcheck:", "req-1"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q: %s", want, out.String())
		}
	}
	if polls.Load() < 3 {
		t.Fatal("CLI did not wait for the result")
	}
	// The request carries references and metadata only.
	if seen["secret"] != "db-password" || seen["runner_id"] != "r-1" {
		t.Fatalf("request: %v", seen)
	}
	target, _ := seen["target"].(map[string]any)
	if target["path"] != "/srv/app/.env" || target["field"] != "DB_PASSWORD" || target["mode"] != "0600" {
		t.Fatalf("target: %v", target)
	}
	if strings.Contains(errout.String(), "test-credential") {
		t.Fatal("debug trace leaked the bearer token")
	}
}

// A server that adds any field outside the closed result is broken: nothing of
// its answer reaches the terminal, in either output mode.
func TestDeployCLIRefusesAnswerWithExtraField(t *testing.T) {
	c := canary.New()
	for _, extra := range []string{"value", "ciphertext", "path", "message"} {
		srv := deployServer(t, func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"ok":true,"request_id":"req-1","fingerprint":"kfp1:k1:abcdefghijklmnop","version":"7","` + extra + `":"` + c.Value(1) + `"}`))
		}, func(http.ResponseWriter) {}, nil)
		for _, json := range []bool{false, true} {
			args := append([]string{}, deployArgs...)
			if json {
				args = append(args, "--json")
			}
			var out, errout bytes.Buffer
			code := run(args, nil, &out, &errout, deployEnv(srv.URL))
			if code == 0 || out.Len() != 0 || c.In(out.String()+errout.String()) {
				t.Fatalf("%s json=%v: exit %d out=%q err=%q", extra, json, code, out.String(), errout.String())
			}
		}
	}
	// Positive control: the same answer without the extra field succeeds.
	srv := deployServer(t, func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"ok":true,"request_id":"req-1","fingerprint":"kfp1:k1:abcdefghijklmnop","version":"7"}`))
	}, func(http.ResponseWriter) {}, nil)
	var out, errout bytes.Buffer
	if run(deployArgs, nil, &out, &errout, deployEnv(srv.URL)) != 0 {
		t.Fatalf("control failed: %s", errout.String())
	}
}

// healthcheck is {status, checked_at} (threat model 4.3): a runner detail the
// contract does not list is refused like any other extra field, and the
// printed healthcheck line carries no kind or duration.
func TestDeployCLIHealthcheckIsExactlyStatusAndCheckedAt(t *testing.T) {
	for _, extra := range []string{`,"kind":"unit-active"`, `,"duration_ms":40`} {
		srv := deployServer(t, func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"ok":true,"request_id":"req-1","healthcheck":{"status":"ok","checked_at":"2026-10-09T12:00:00Z"` + extra + `}}`))
		}, func(http.ResponseWriter) {}, nil)
		var out, errout bytes.Buffer
		if code := run(deployArgs, nil, &out, &errout, deployEnv(srv.URL)); code == 0 || out.Len() != 0 {
			t.Fatalf("%s: exit %d out=%q", extra, code, out.String())
		}
	}
	srv := deployServer(t, func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"ok":true,"request_id":"req-1","healthcheck":{"status":"ok","checked_at":"2026-10-09T12:00:00Z"}}`))
	}, func(http.ResponseWriter) {}, nil)
	var out, errout bytes.Buffer
	if code := run(deployArgs, nil, &out, &errout, deployEnv(srv.URL)); code != 0 {
		t.Fatalf("control: exit %d: %s", code, errout.String())
	}
	if line := healthLine(out.String()); line == "" || strings.Contains(line, "ms") || strings.Contains(line, "(") {
		t.Fatalf("healthcheck line: %q", line)
	}
}

func healthLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "healthcheck:") {
			return l
		}
	}
	return ""
}

// The eleventh deploy's closed class is printed as itself, not folded into
// permission_denied and not as an unexpected value.
func TestDeployCLIPrintsRateLimited(t *testing.T) {
	srv := deployServer(t, func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error_class":"rate_limited","message":"deployment rate limit reached","request_id":"req-1"}`))
	}, func(http.ResponseWriter) {}, nil)
	var out, errout bytes.Buffer
	code := run(deployArgs, nil, &out, &errout, deployEnv(srv.URL))
	if code == 0 || !strings.Contains(errout.String()+out.String(), "rate_limited") {
		t.Fatalf("exit %d out=%q err=%q", code, out.String(), errout.String())
	}
}

func TestDeployCLIExitCodes(t *testing.T) {
	deployPollEvery = 10 * time.Millisecond
	for name, tc := range map[string]struct {
		status int
		body   string
		want   int
		print  string
	}{
		"approval":      {http.StatusAccepted, `{"ok":false,"request_id":"req-1","approval":{"id":"a-1","status":"requested","url":"https://keep.example.test/console/approvals/a-1"}}`, 3, "https://keep.example.test/console/approvals/a-1"},
		"runner-failed": {http.StatusOK, `{"ok":false,"request_id":"req-1","error_class":"target_write_failed"}`, 1, "target_write_failed"},
		"server-error":  {http.StatusBadRequest, `{"error_class":"invalid_argument","message":"deployment rejected: secret \"db-password\", target kind env-file","request_id":"req-9"}`, 1, ""},
	} {
		t.Run(name, func(t *testing.T) {
			srv := deployServer(t, func(w http.ResponseWriter) { w.WriteHeader(tc.status); _, _ = w.Write([]byte(tc.body)) }, func(http.ResponseWriter) {}, nil)
			var out, errout bytes.Buffer
			if code := run(deployArgs, nil, &out, &errout, deployEnv(srv.URL)); code != tc.want {
				t.Fatalf("exit %d want %d: %s %s", code, tc.want, out.String(), errout.String())
			}
			if !strings.Contains(out.String()+errout.String(), tc.print) {
				t.Fatalf("missing %q: %s %s", tc.print, out.String(), errout.String())
			}
		})
	}
	// A result that never arrives is exit 4, not success.
	srv := deployServer(t, func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":false,"request_id":"req-1"}`))
	},
		func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"ok":false,"request_id":"req-1"}`))
		}, nil)
	args := append(append([]string{}, deployArgs[:len(deployArgs)-2]...), "--wait", "50ms")
	if code := run(args, nil, &bytes.Buffer{}, &bytes.Buffer{}, deployEnv(srv.URL)); code != 4 {
		t.Fatalf("pending exit %d", code)
	}
}

func TestDeployCLIRequiresItsArguments(t *testing.T) {
	for _, args := range [][]string{
		{"deploy"},
		{"deploy", "db-password"},
		{"deploy", "db-password", "--runner", "r-1", "--target", "/x"},
		{"deploy", "db-password", "--target", "/x", "--uid", "1", "--gid", "1"},
		{"deploy", "db-password", "--runner", "r-1", "--uid", "1", "--gid", "1"},
		{"deploy", "db-password", "--runner", "r-1", "--target", "/x", "--gid", "1"},
		{"deploy", "db-password", "--runner", "r-1", "--target", "/x", "--uid", "1"},
		{"deploy", "db-password", "--runner", "r-1", "--target", "/x", "--uid", "1", "--gid", "1", "--value", "x"},
		{"deploy", "db-password", "--runner", "r-1", "--target", "/x", "--uid", "1", "--gid", "1", "extra"},
	} {
		var out, errout bytes.Buffer
		if code := run(args, nil, &out, &errout, deployEnv("http://127.0.0.1:1")); code != 2 {
			t.Fatalf("%v: exit %d", args, code)
		}
	}
}
