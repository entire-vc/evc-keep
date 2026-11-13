package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// The peer deliberately violates the REST contract to test the outward boundary.
func metadataAnswer(t *testing.T, tool string, poll bool, body map[string]any) (string, int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if poll && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "request_id": testRequest})
			return
		}
		if (tool == "rotate" && r.Method == http.MethodPost) || (body["approval"] != nil && body["approval"].(map[string]any)["status"] == "requested") {
			w.WriteHeader(http.StatusAccepted)
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	args := deployArgs(nil)
	if tool == "rotate" {
		args = rotateArgs(nil)
	}
	if !poll {
		args["wait_seconds"] = 0
	}
	out := session(t, newTestServer(t, srv.URL, "tok"), call(1, tool, args))
	return out, calls.Load()
}

func TestDeployMetadataIsClosedOnStartAndPoll(t *testing.T) {
	old := pollEvery
	pollEvery = time.Millisecond
	defer func() { pollEvery = old }()
	for _, poll := range []bool{false, true} {
		phase := "post"
		if poll {
			phase = "poll"
		}
		for _, field := range []string{"version", "version-control", "approval-id", "approval-status", "approval-url", "approval-extra"} {
			t.Run(phase+"/"+field, func(t *testing.T) {
				c := canary.New()
				value := c.Value(1)
				requireDetectorSees(t, c, value)
				body := map[string]any{"ok": true, "request_id": testRequest, "version": "2", "fingerprint": "kfp1:k:abcdefghijklmnop"}
				if strings.HasPrefix(field, "approval-") {
					body = map[string]any{"ok": false, "request_id": testRequest}
					a := map[string]any{"id": testSecretID, "status": "requested", "url": "https://keep.example/approvals/" + testSecretID}
					switch field {
					case "approval-id":
						a["id"] = value
					case "approval-status":
						a["status"] = value
					case "approval-url":
						a["url"] = "https://keep.example/ " + value
					case "approval-extra":
						a["value"] = value
					}
					body["approval"] = a
				} else {
					body["version"] = value
					if field == "version-control" {
						body["version"] = value + "\n"
					}
				}
				out, calls := metadataAnswer(t, "deploy", poll, body)
				wantCalls := int32(1)
				if poll {
					wantCalls = 2
				}
				if calls != wantCalls || !strings.Contains(out, `"isError":true`) || c.In(out) {
					t.Fatalf("hostile metadata: calls=%d isError=%t leaked=%t", calls, strings.Contains(out, `"isError":true`), c.In(out))
				}
			})
		}
	}
}

func TestApprovalValidationIsSharedOnStartAndPoll(t *testing.T) {
	old := pollEvery
	pollEvery = time.Millisecond
	defer func() { pollEvery = old }()
	for _, tool := range []string{"deploy", "rotate"} {
		for _, poll := range []bool{false, true} {
			phase := "post"
			if poll {
				phase = "poll"
			}
			for _, tc := range []struct {
				name, field, value string
				valid              bool
			}{
				{"requested", "status", "requested", true},
				{"approved", "status", "approved", true},
				{"rejected", "status", "rejected", true},
				{"expired", "status", "expired", true},
				{"empty-id", "id", "", false},
				{"text-id", "id", "arbitrary", false},
				{"empty-status", "status", "", false},
				{"text-status", "status", "pending", false},
				{"empty-url", "url", "", false},
				{"url-limit", "url", "https://keep.example/" + strings.Repeat("a", 491), true},
				{"long-url", "url", "https://keep.example/" + strings.Repeat("a", 492), false},
				{"space-url", "url", "https://keep.example/ a", false},
				{"tab-url", "url", "https://keep.example/\ta", false},
				{"cr-url", "url", "https://keep.example/\ra", false},
				{"lf-url", "url", "https://keep.example/\na", false},
			} {
				t.Run(tool+"/"+phase+"/"+tc.name, func(t *testing.T) {
					a := map[string]any{"id": testSecretID, "status": "requested", "url": "https://keep.example/approvals/" + testSecretID}
					a[tc.field] = tc.value
					out, _ := metadataAnswer(t, tool, poll, map[string]any{"ok": false, "request_id": testRequest, "approval": a})
					if strings.Contains(out, `"isError":true`) == tc.valid {
						t.Fatal("approval validation disagrees with contract")
					}
				})
			}
		}
	}
}

func TestDeployVersionShape(t *testing.T) {
	for _, version := range []string{"", "1", "999999999", "0", "01", "1000000000", "v2", "2\n"} {
		t.Run(version, func(t *testing.T) {
			valid := version == "" || version == "1" || version == "999999999"
			body := map[string]any{"ok": true, "request_id": testRequest, "version": version, "fingerprint": "kfp1:k:abcdefghijklmnop"}
			if version == "" {
				body = map[string]any{"ok": false, "request_id": testRequest}
			}
			out, _ := metadataAnswer(t, "deploy", false, body)
			if strings.Contains(out, `"isError":true`) == valid {
				t.Fatal("version validation disagrees with contract")
			}
		})
	}
}

func TestDeployStatusMatchesResult(t *testing.T) {
	old := pollEvery
	pollEvery = time.Millisecond
	defer func() { pollEvery = old }()
	for _, tc := range []struct {
		name   string
		status int
		extra  map[string]any
	}{
		{"other-success-status", http.StatusCreated, nil},
		{"accepted-ok", http.StatusAccepted, map[string]any{"ok": true, "version": "2", "fingerprint": "kfp1:k:abcdefghijklmnop"}},
		{"accepted-class", http.StatusAccepted, map[string]any{"error_class": "internal"}},
		{"version-before-ok", http.StatusOK, map[string]any{"version": "2"}},
		{"fingerprint-before-ok", http.StatusOK, map[string]any{"fingerprint": "kfp1:k:abcdefghijklmnop"}},
		{"class-on-ok", http.StatusOK, map[string]any{"ok": true, "version": "2", "fingerprint": "kfp1:k:abcdefghijklmnop", "error_class": "internal"}},
		{"ok-without-version", http.StatusOK, map[string]any{"ok": true, "fingerprint": "kfp1:k:abcdefghijklmnop"}},
		{"ok-without-fingerprint", http.StatusOK, map[string]any{"ok": true, "version": "2"}},
	} {
		for _, poll := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "/post", true: "/poll"}[poll], func(t *testing.T) {
				body := map[string]any{"ok": false, "request_id": testRequest}
				for k, v := range tc.extra {
					body[k] = v
				}
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if poll && r.Method == http.MethodPost {
						w.WriteHeader(http.StatusAccepted)
						_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "request_id": testRequest})
						return
					}
					w.WriteHeader(tc.status)
					_ = json.NewEncoder(w).Encode(body)
				}))
				t.Cleanup(srv.Close)
				out := session(t, newTestServer(t, srv.URL, "tok"), call(1, "deploy", deployArgs(map[string]any{"wait_seconds": 1})))
				if !strings.Contains(out, `"isError":true`) {
					t.Fatal("inconsistent deployment result accepted")
				}
			})
		}
	}
}

func TestDeployCheckedAtUsesUTCSeconds(t *testing.T) {
	for _, stamp := range []string{"2026-10-31T23:45:12.123456789+03:15", "2026-10-31T20:30:12Z"} {
		out, _ := metadataAnswer(t, "deploy", false, map[string]any{"ok": true, "request_id": testRequest, "version": "2", "fingerprint": "kfp1:k:abcdefghijklmnop", "healthcheck": map[string]any{"status": "ok", "checked_at": stamp}})
		got := answers(t, out)
		if got[0].Result.IsError || !strings.Contains(got[0].Result.Content[0].Text, `"checked_at":"2026-10-31T20:30:12Z"`) {
			t.Fatal("checked_at was not normalized to UTC seconds")
		}
	}
}

// A deploy answer whose request_id is not of the closed shape is refused whole,
// on start and on poll; the same body with a valid id is the positive control.
func TestDeployRequestIDShapeIsClosedOnStartAndPoll(t *testing.T) {
	old := pollEvery
	pollEvery = time.Millisecond
	defer func() { pollEvery = old }()
	for _, poll := range []bool{false, true} {
		phase := "post"
		if poll {
			phase = "poll"
		}
		for name, id := range map[string]string{"control": testRequest, "slash": "../x", "space": "a b", "newline": testRequest + "\n", "long": strings.Repeat("a", 200)} {
			t.Run(phase+"/"+name, func(t *testing.T) {
				out, _ := metadataAnswer(t, "deploy", poll, map[string]any{"ok": false, "request_id": id})
				refused := strings.Contains(out, `"isError":true`)
				if refused != (name != "control") {
					t.Fatalf("request_id %q: refused=%t", id, refused)
				}
				if name != "control" && strings.Contains(out, id) {
					t.Fatalf("hostile request_id echoed: %q", out)
				}
			})
		}
	}
}

// A deploy that wrote the value but whose consumer did not come up reaches the
// agent with its class, version and fingerprint; any other failed answer that
// names a version is refused.
func TestDeployFailedAnswerShape(t *testing.T) {
	const fp = "kfp1:k:abcdefghijklmnop"
	for _, tc := range []struct {
		name  string
		extra map[string]any
		ok    bool
	}{
		{"healthcheck-failed-with-both", map[string]any{"error_class": "healthcheck_failed", "version": "3", "fingerprint": fp, "healthcheck": map[string]any{"status": "failed"}}, true},
		{"api-class-without-version", map[string]any{"error_class": "not_ready"}, true},
		{"runner-class-without-version", map[string]any{"error_class": "target_write_failed"}, true},
		{"runner-class-with-version", map[string]any{"error_class": "target_write_failed", "version": "3"}, false},
		{"runner-class-with-both", map[string]any{"error_class": "target_write_failed", "version": "3", "fingerprint": fp}, false},
		{"healthcheck-failed-version-only", map[string]any{"error_class": "healthcheck_failed", "version": "3"}, false},
		{"healthcheck-failed-fingerprint-only", map[string]any{"error_class": "healthcheck_failed", "fingerprint": fp}, false},
		{"unknown-class", map[string]any{"error_class": "Healthcheck_Failed"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{"ok": false, "request_id": testRequest}
			for k, v := range tc.extra {
				body[k] = v
			}
			out, _ := metadataAnswer(t, "deploy", false, body)
			if strings.Contains(out, `"isError":true`) && strings.Contains(out, "unexpected shape") == tc.ok {
				t.Fatalf("shape verdict wrong: %s", out)
			}
			if tc.ok {
				for _, want := range []string{tc.extra["error_class"].(string), "request_id"} {
					if !strings.Contains(out, want) {
						t.Fatalf("answer lacks %q: %s", want, out)
					}
				}
				if v, has := tc.extra["version"]; has && !strings.Contains(out, v.(string)) {
					t.Fatalf("answer lacks version: %s", out)
				}
			} else if !strings.Contains(out, "unexpected shape") {
				t.Fatalf("answer accepted: %s", out)
			}
		})
	}
}
