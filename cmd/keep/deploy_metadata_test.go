package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

// Exercise the real HTTP boundary in both output modes, on POST and polling.
// A malformed metadata field rejects the whole answer before it is printed.
func TestDeployCLIMetadataNoLeak(t *testing.T) {
	old := deployPollEvery
	deployPollEvery = time.Millisecond
	t.Cleanup(func() { deployPollEvery = old })
	c := canary.New()
	// Longer than a request id: a valid short id is intentionally public metadata.
	planted := c.Value(1) + "-metadata"
	encodings := []string{planted, hex.EncodeToString([]byte(planted)), base64.StdEncoding.EncodeToString([]byte(planted)), "\x1b[31m" + planted + "\n"}
	for _, v := range encodings {
		if !c.In(v) {
			t.Fatal("canary detector missed positive control")
		}
	}
	fields := []string{"fingerprint", "version", "approval.id", "approval.status", "approval.url"}
	for _, field := range fields {
		for i, v := range encodings {
			t.Run(field+"/encoding-"+string(rune('0'+i)), func(t *testing.T) {
				exerciseDeployMetadata(t, func(r *deployResult, server string) {
					switch field {
					case "fingerprint":
						r.Fingerprint = v
					case "version":
						r.Version = v
					case "approval.id":
						r.Approval.ID = v
						r.Approval.URL = server + "/console/approvals/" + v
					case "approval.status":
						r.Approval.Status = v
					case "approval.url":
						r.Approval.URL += "?value=" + v
					}
				}, false, c, false)
			})
		}
	}
	// Healthy answers must still pass through these exact output captures.
	exerciseDeployMetadata(t, nil, true, c, false)
}

func TestDeployCLIMetadataShapes(t *testing.T) {
	old := deployPollEvery
	deployPollEvery = time.Millisecond
	t.Cleanup(func() { deployPollEvery = old })
	cases := map[string]func(*deployResult, string){
		"fingerprint-upper":      func(r *deployResult, _ string) { r.Fingerprint = "kfp1:k1:ABCDEFGHIJKLMNOP" },
		"fingerprint-short":      func(r *deployResult, _ string) { r.Fingerprint = "kfp1:k1:abcdefghijklmno" },
		"fingerprint-long":       func(r *deployResult, _ string) { r.Fingerprint += "a" },
		"fingerprint-key":        func(r *deployResult, _ string) { r.Fingerprint = "kfp1:bad_key:abcdefghijklmnop" },
		"version-zero":           func(r *deployResult, _ string) { r.Version = "0" },
		"version-leading-zero":   func(r *deployResult, _ string) { r.Version = "01" },
		"version-sign":           func(r *deployResult, _ string) { r.Version = "+1" },
		"version-negative":       func(r *deployResult, _ string) { r.Version = "-1" },
		"version-space":          func(r *deployResult, _ string) { r.Version = "1 " },
		"version-overflow":       func(r *deployResult, _ string) { r.Version = "9223372036854775808" },
		"approval-id-empty":      func(r *deployResult, _ string) { r.Approval.ID = "" },
		"approval-id-long":       func(r *deployResult, _ string) { r.Approval.ID = strings.Repeat("a", 37) },
		"approval-id-shape":      func(r *deployResult, _ string) { r.Approval.ID = "bad_id" },
		"approval-status-empty":  func(r *deployResult, _ string) { r.Approval.Status = "" },
		"approval-status-case":   func(r *deployResult, _ string) { r.Approval.Status = "Requested" },
		"approval-status-prefix": func(r *deployResult, _ string) { r.Approval.Status = "requested-extra" },
		"url-empty":              func(r *deployResult, _ string) { r.Approval.URL = "" },
		// The server is plain http on loopback, so an https link is a scheme mismatch.
		"url-https-on-http-server": func(r *deployResult, _ string) {
			r.Approval.URL = strings.Replace(r.Approval.URL, "http:", "https:", 1)
		},
		"url-relative":     func(r *deployResult, _ string) { r.Approval.URL = "/console/approvals/a-1" },
		"url-foreign-host": func(r *deployResult, _ string) { r.Approval.URL = "https://other.example.test/console/approvals/a-1" },
		"url-port":         func(r *deployResult, _ string) { r.Approval.URL = "https://127.0.0.1:1/console/approvals/a-1" },
		"url-userinfo": func(r *deployResult, _ string) {
			r.Approval.URL = strings.Replace(r.Approval.URL, "http://", "http://user@", 1)
		},
		"url-query":        func(r *deployResult, _ string) { r.Approval.URL += "?x=1" },
		"url-fragment":     func(r *deployResult, _ string) { r.Approval.URL += "#x" },
		"url-empty-query":  func(r *deployResult, _ string) { r.Approval.URL += "?" },
		"url-other-id":     func(r *deployResult, _ string) { r.Approval.URL += "x" },
		"url-encoded-path": func(r *deployResult, _ string) { r.Approval.URL = strings.Replace(r.Approval.URL, "/a-1", "/%61-1", 1) },
		"url-malformed":    func(r *deployResult, _ string) { r.Approval.URL = "https://%zz" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) { exerciseDeployMetadata(t, change, false, canary.New(), false) })
	}
	for _, status := range []string{"requested", "approved", "rejected", "expired"} {
		t.Run(status, func(t *testing.T) {
			exerciseDeployMetadata(t, func(r *deployResult, server string) {
				r.Approval.Status = status
				r.Approval.ID = "01900000-0000-7000-8000-000000000001"
				r.Approval.URL = server + "/console/approvals/" + r.Approval.ID
				r.Version = "9223372036854775807"
			}, true, canary.New(), false)
		})
	}
	t.Run("optional-metadata-absent", func(t *testing.T) {
		exerciseDeployMetadata(t, func(r *deployResult, _ string) { r.Fingerprint = ""; r.Version = ""; r.Approval = nil }, true, canary.New(), false)
	})
}

// The built CLI must intercept both streams too, including debug mode.
func TestDeployCLIMetadataBinaryNoLeak(t *testing.T) {
	c := canary.New()
	exerciseDeployMetadata(t, func(r *deployResult, _ string) { r.Fingerprint = c.Value(1) }, false, c, true)
	exerciseDeployMetadata(t, nil, true, c, true)
}

func exerciseDeployMetadata(t *testing.T, change func(*deployResult, string), valid bool, c canary.Canary, binary bool) {
	t.Helper()
	for _, polling := range []bool{false, true} {
		for _, asJSON := range []bool{false, true} {
			var serverURL string
			calls := 0
			var sent deployResult
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls++
				if req.Method == http.MethodPost && polling {
					w.WriteHeader(http.StatusAccepted)
					_, _ = w.Write([]byte(`{"ok":false,"request_id":"req-1"}`))
					return
				}
				if (polling && (req.Method != http.MethodGet || req.URL.Path != "/v1/deployments/req-1")) || (!polling && req.Method != http.MethodPost) {
					t.Error("unexpected deployment request")
				}
				res := deployResult{OK: true, RequestID: "req-1", Fingerprint: "kfp1:k1:abcdefghijklmnop", Version: "7", Approval: &deployApproval{ID: "a-1", Status: "requested", URL: serverURL + "/console/approvals/a-1"}}
				if change != nil {
					change(&res, serverURL)
				}
				sent = res
				_ = json.NewEncoder(w).Encode(res)
			}))
			// Publish the address before starting handler goroutines, including
			// when the HTTP client runs in a separate process.
			serverURL = "http://" + srv.Listener.Addr().String()
			srv.Start()
			var out, errout bytes.Buffer
			args := append(append([]string{}, deployArgs...), "--debug")
			if asJSON {
				args = append(args, "--json")
			}
			code := 0
			if binary {
				cmd := exec.Command(keepBinPath, args...) //nolint:gosec // G204: test-built binary and fixed arguments
				cmd.Env = []string{"KEEP_SERVER=" + srv.URL, "KEEP_ORG=test-org", "KEEP_TOKEN=test-credential"}
				cmd.Stdout, cmd.Stderr = &out, &errout
				if err := cmd.Run(); err != nil {
					if exit, ok := err.(*exec.ExitError); ok {
						code = exit.ExitCode()
					} else {
						t.Fatal("cannot run test-built CLI")
					}
				}
			} else {
				code = run(args, nil, &out, &errout, deployEnv(srv.URL))
			}
			srv.Close()
			wantCalls := 1
			if polling {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatalf("polling=%v: got %d calls, want %d", polling, calls, wantCalls)
			}
			if c.In(out.String()+errout.String()) || strings.Contains(out.String()+errout.String(), "test-credential") {
				t.Errorf("polling=%v json=%v: metadata reached CLI output", polling, asJSON)
			}
			if !valid {
				if code != 1 || out.Len() != 0 || !strings.Contains(errout.String(), "invalid deploy response") {
					t.Errorf("polling=%v json=%v: malformed response accepted or error not static (exit=%d stdout bytes=%d)", polling, asJSON, code, out.Len())
				}
			} else {
				wantCode := 0
				if sent.Approval != nil {
					wantCode = exitDeployApproval
				}
				if code != wantCode || out.Len() == 0 {
					t.Errorf("healthy response rejected: exit=%d", code)
				}
				for _, value := range []string{sent.Fingerprint, sent.Version} {
					if value != "" && !strings.Contains(out.String(), value) {
						t.Error("healthy metadata was dropped")
					}
				}
				if a := sent.Approval; a != nil {
					for _, value := range []string{a.ID, a.Status, a.URL} {
						if !strings.Contains(out.String(), value) {
							t.Error("healthy approval metadata was dropped")
						}
					}
				}
				if !strings.Contains(out.String(), "req-1") {
					t.Error("healthy response did not reach stdout")
				}
			}
		}
	}
}

// The approval link must carry the server's own scheme: https, or http only
// when the server itself is plain http on a loopback host (the quickstart).
func TestValidDeployMetadataApprovalScheme(t *testing.T) {
	const id = "01900000-0000-7000-8000-000000000001"
	link := func(scheme, host string) string { return scheme + "://" + host + "/console/approvals/" + id }
	cases := []struct {
		name   string
		server string
		url    string
		want   bool
	}{
		{"http-ipv4-loopback", "http://127.0.0.1:8080", link("http", "127.0.0.1:8080"), true},
		{"http-localhost", "http://localhost:8080", link("http", "localhost:8080"), true},
		{"http-ipv6-loopback", "http://[::1]:8080", link("http", "[::1]:8080"), true},
		{"https-server-https-link", "https://keep.example.test", link("https", "keep.example.test"), true},
		{"https-server-http-link-downgrade", "https://keep.example.test", link("http", "keep.example.test"), false},
		{"https-loopback-server-http-link", "https://127.0.0.1:8443", link("http", "127.0.0.1:8443"), false},
		{"http-loopback-other-host", "http://127.0.0.1:8080", link("http", "127.0.0.2:8080"), false},
		{"http-loopback-other-port", "http://127.0.0.1:8080", link("http", "127.0.0.1:8081"), false},
		{"http-loopback-https-link", "http://127.0.0.1:8080", link("https", "127.0.0.1:8080"), false},
		{"http-loopback-userinfo", "http://127.0.0.1:8080", "http://u@127.0.0.1:8080/console/approvals/" + id, false},
		{"http-loopback-query", "http://127.0.0.1:8080", link("http", "127.0.0.1:8080") + "?x=1", false},
		{"http-loopback-fragment", "http://127.0.0.1:8080", link("http", "127.0.0.1:8080") + "#x", false},
		{"http-non-loopback-server-http-link", "http://keep.example.test", link("http", "keep.example.test"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := deployResult{Approval: &deployApproval{ID: id, Status: "requested", URL: c.url}}
			if got := validDeployMetadata(r, c.server); got != c.want {
				t.Errorf("validDeployMetadata(server %s) = %v, want %v", c.server, got, c.want)
			}
		})
	}
}
