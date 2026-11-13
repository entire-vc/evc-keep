package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/entire-vc/evc-keep/internal/reqid"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// requestIDCases builds request ids around the canary: the server's contract
// (internal/reqid.Valid) is [A-Za-z0-9-]{1,36}, and the cap exists because a
// token's random part is 52 characters. leaks is true for every shape the CLI
// must not print.
func requestIDCases(c canary.Canary) []struct {
	name string
	id   string
	ok   bool
} {
	base := c.Value(0)[:len("kc")+24]
	pad := func(n int) string { return base + strings.Repeat("a", n-len(base)) }
	return []struct {
		name string
		id   string
		ok   bool
	}{
		{"len-36-boundary", pad(36), true},
		{"len-37", pad(37), false},
		{"len-52-credential", pad(52), false},
		{"len-64", pad(64), false},
		{"len-65", pad(65), false},
		{"underscore", base + "_x", false},
		{"dot", base + ".x", false},
		{"control", base + "\x1b[2J", false},
		{"newline", base + "\nx", false},
		{"empty", "", true},
		{"req-1", "req-1", true},
		{"uuid", "0190a5c2-7b3e-7d4f-8a1b-2c3d4e5f6a7b", true},
	}
}

// TestRequestIDContractNoLeak: a request_id outside the server's 1–36
// [A-Za-z0-9-] contract never reaches the terminal through any CLI sink, and
// one inside it still does (threat model §4.3).
func TestRequestIDContractNoLeak(t *testing.T) {
	const runnerID = "11111111-2222-4333-8444-555555555555"
	for _, tc := range requestIDCases(canary.New()) {
		if reqid.Valid(tc.id) != (tc.ok && tc.id != "") {
			t.Fatalf("%s: case disagrees with reqid.Valid", tc.name)
		}
	}
	for _, status := range []int{http.StatusOK, http.StatusBadRequest} {
		for i, probe := range requestIDCases(canary.New()) {
			name := "revoke-" + http.StatusText(status) + "/" + probe.name
			t.Run(name, func(t *testing.T) {
				can := canary.New()
				tc := requestIDCases(can)[i]
				id := tc.id
				body, _ := json.Marshal(map[string]any{"ok": true, "error_class": "validation_error", "message": "m", "request_id": id})
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(status)
					_, _ = w.Write(body)
				}))
				defer srv.Close()
				t.Setenv("KEEP_ADMIN_TOKEN", testAdminTokenFixture)
				caPath := writePEMCert(t, srv.Certificate())
				rc, stdout, stderr := captureOutput(t, func() int {
					return runRunnerRevoke([]string{"-server", srv.URL, "-server-ca", caPath, runnerID})
				})
				if wantRC := map[bool]int{true: 0, false: 1}[status == http.StatusOK]; rc != wantRC {
					t.Fatalf("rc=%d, want %d", rc, wantRC)
				}
				out := stdout + stderr
				if strings.Contains(out, testAdminTokenFixture) {
					t.Fatal("bearer reached output")
				}
				if tc.ok {
					if tc.id != "" && !strings.Contains(out, "request_id="+tc.id) {
						t.Errorf("valid id dropped (out len=%d)", len(out))
					}
				} else if can.In(out) {
					t.Errorf("request_id credential reached output (len=%d)", len(out))
				}
			})
		}
	}
	t.Run("apiError.Error-and-printAPIError", func(t *testing.T) {
		for i := range requestIDCases(canary.New()) {
			can := canary.New()
			tc := requestIDCases(can)[i]
			id := tc.id
			e := &apiError{ErrorClass: "validation_error", Message: "m", RequestID: id}
			var sb strings.Builder
			body, _ := json.Marshal(e)
			printAPIError(&sb, strings.NewReader(string(body)))
			for sink, out := range map[string]string{"Error": e.Error(), "printAPIError": sb.String()} {
				if !tc.ok && can.In(out) {
					t.Errorf("%s/%s: credential reached output (len=%d)", tc.name, sink, len(out))
				}
				if tc.ok && tc.id != "" && !strings.Contains(out, "request_id="+tc.id) {
					t.Errorf("%s/%s: valid id dropped", tc.name, sink)
				}
			}
		}
	})
	t.Run("detector-positive-control", func(t *testing.T) {
		can := canary.New()
		if !can.In("x " + can.Value(0)[:26] + "_y") {
			t.Fatal("canary detector is blind")
		}
	})
}
