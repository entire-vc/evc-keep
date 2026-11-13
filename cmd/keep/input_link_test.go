package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func TestInputLinkCLIClosedOutput(t *testing.T) {
	probe := canary.New()
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/input-links" || r.Method != http.MethodPost {
			t.Error("issuance route")
		}
		var request map[string]string
		if json.NewDecoder(r.Body).Decode(&request) != nil || request["secret"] != "sample" || request["ttl"] != "1h" {
			t.Error("issuance request")
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"url": "https://keep.example.invalid/input/test", "request_id": "test-request", "expires_at": time.Now().Add(time.Hour), "value": probe.Value(1)})
	}))
	defer srv.Close()
	getenv := func(k string) string {
		switch k {
		case "KEEP_SERVER":
			return srv.URL
		case "KEEP_ORG":
			return "test-org"
		case "KEEP_TOKEN":
			return "test-credential"
		}
		return ""
	}
	var out, errout bytes.Buffer
	if run([]string{"input-link", "sample", "--ttl", "1h", "--debug"}, nil, &out, &errout, getenv) != 0 {
		t.Fatal("input-link CLI failed")
	}
	if probe.In(out.String()) || probe.In(errout.String()) {
		t.Fatal("CLI printed extra response data")
	}
	var link intake.Issued
	if json.Unmarshal(out.Bytes(), &link) != nil || link.URL == "" || calls != 1 {
		t.Fatal("CLI link output")
	}
	if run([]string{"input-link", "sample", "--ttl", "25h"}, nil, &out, &errout, getenv) != 2 || calls != 1 {
		t.Fatal("CLI sent invalid TTL")
	}
}

// inputLinkFixedExpiry is a fixed instant so the printed expires_at can be
// compared exactly instead of by field name.
var inputLinkFixedExpiry = time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)

const inputLinkTestURL = "https://keep.example.invalid/input/test"

// runInputLinkAgainst issues one link from a server answering with id and
// returns stdout, stderr and the exit code. debug adds --debug.
func runInputLinkAgainst(t *testing.T, id string, debug bool) (string, string, int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(intake.Issued{URL: inputLinkTestURL, RequestID: id, ExpiresAt: inputLinkFixedExpiry})
	}))
	defer srv.Close()
	args := []string{"input-link", "sample", "--ttl", "1h"}
	if debug {
		args = append(args, "--debug")
	}
	var out, errout bytes.Buffer
	code := run(args, nil, &out, &errout, inputLinkEnv(srv.URL))
	return out.String(), errout.String(), code
}

// requireInputLinkOutput decodes stdout and demands the exact url, expiry and
// request_id.
func requireInputLinkOutput(t *testing.T, stdout, wantID string) {
	t.Helper()
	var got intake.Issued
	if json.Unmarshal([]byte(stdout), &got) != nil {
		t.Fatal("stdout is not the JSON link")
	}
	if got.URL != inputLinkTestURL || !got.ExpiresAt.Equal(inputLinkFixedExpiry) || got.RequestID != wantID {
		t.Fatal("printed url, expires_at or request_id differ from the expected values")
	}
}

// TestInputLinkRejectsInvalidRequestID: a request_id outside internal/reqid's
// shape (here a 52-character canary, the size of a token's random part) is
// replaced by a fixed placeholder and reaches neither stdout nor stderr, with
// --debug off and on; the one-time url and expires_at are printed unchanged.
func TestInputLinkRejectsInvalidRequestID(t *testing.T) {
	probe := canary.New()
	if !probe.In("request_id=" + probe.Value(1)) {
		t.Fatal("canary detector control")
	}
	for name, id := range map[string]string{
		"canary-52":  probe.Value(1) + strings.Repeat("x", 52-len(probe.Value(1))),
		"37-chars":   strings.Repeat("a", 37),
		"underscore": "req_1",
		"control":    "req\x1b[31m",
		"empty":      "",
	} {
		for _, debug := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/debug=%v", name, debug), func(t *testing.T) {
				stdout, stderr, code := runInputLinkAgainst(t, id, debug)
				if code != 0 {
					t.Fatal("input-link failed instead of replacing the invalid request_id")
				}
				escaped, _ := json.Marshal(id)
				for _, stream := range []string{stdout, stderr} {
					if probe.In(stream) || (id != "" && (strings.Contains(stream, id) || strings.Contains(stream, strings.Trim(string(escaped), `"`)))) {
						t.Fatal("invalid request_id was printed")
					}
				}
				requireInputLinkOutput(t, stdout, unexpectedValue)
			})
		}
	}
}

func TestInputLinkPrintsValidRequestID(t *testing.T) {
	for name, id := range map[string]string{
		"len-1":  "a",
		"len-36": strings.Repeat("a", 35) + "-",
		"uuid":   "0b2f6c1e-1111-4222-8333-444455556666",
	} {
		for _, debug := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/debug=%v", name, debug), func(t *testing.T) {
				stdout, _, code := runInputLinkAgainst(t, id, debug)
				if code != 0 {
					t.Fatal("input-link failed on a valid request_id")
				}
				requireInputLinkOutput(t, stdout, id)
			})
		}
	}
}

func inputLinkEnv(url string) func(string) string {
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

func TestInputLinkCLITokenAndRedirectGuards(t *testing.T) {
	token := canary.New().Value(1)
	probe := canary.Of(token)
	if !probe.In("https://keep.example.invalid/input/" + token) {
		t.Fatal("token detector control")
	}
	var followed int
	for _, status := range []int{http.StatusCreated, http.StatusBadRequest, http.StatusTemporaryRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/input-links" {
					followed++
					w.WriteHeader(http.StatusCreated)
					_ = json.NewEncoder(w).Encode(intake.Issued{URL: "https://keep.example.invalid/input/" + token, RequestID: "test", ExpiresAt: time.Now().Add(time.Hour)})
					return
				}
				if status == http.StatusTemporaryRedirect {
					w.Header().Set("Location", "/input/"+token)
				}
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(intake.Issued{URL: "https://keep.example.invalid/input/" + token, RequestID: "test", ExpiresAt: time.Now().Add(time.Hour)})
			}))
			defer srv.Close()
			getenv := func(k string) string {
				switch k {
				case "KEEP_SERVER":
					return srv.URL
				case "KEEP_ORG":
					return "test-org"
				case "KEEP_TOKEN":
					return "test-credential"
				}
				return ""
			}
			var out, stderr bytes.Buffer
			code := run([]string{"input-link", "sample", "--debug"}, nil, &out, &stderr, getenv)
			if probe.In(stderr.String()) {
				t.Fatal("input token escaped to CLI stderr")
			}
			if followed != 0 {
				t.Fatal("input-link CLI followed redirect")
			}
			if status == http.StatusCreated {
				if code != 0 || !probe.In(out.String()) {
					t.Fatal("issued link missing from stdout")
				}
			} else if code == 0 || out.Len() != 0 || stderr.Len() == 0 {
				t.Fatal("rejected issuance output")
			}
		})
	}
}

// TestInputLinkResponseBoundary: the 201 body must be exactly one JSON document
// of at most 8192 bytes. Trailing junk, a second document and an oversized body
// (even with a valid prefix and a whitespace-only tail) are refused with empty
// stdout and a static stderr that never carries the synthetic label, with
// --debug off and on, for both Content-Length and chunked framing.
func TestInputLinkResponseBoundary(t *testing.T) {
	probe := canary.New()
	label := probe.Value(1)
	valid, _ := json.Marshal(intake.Issued{URL: inputLinkTestURL, RequestID: "test-request", ExpiresAt: inputLinkFixedExpiry})
	pad := func(n int) string { return strings.Repeat(" ", n) }
	cases := []struct {
		name string
		body string
		ok   bool
	}{
		{"valid", string(valid), true},
		{"trailing-whitespace", string(valid) + " \n\t\r\n", true},
		{"exactly-8192", string(valid) + pad(8192-len(valid)), true},
		{"trailing-junk", string(valid) + "]", false},
		{"trailing-junk-label", string(valid) + label, false},
		{"second-document", string(valid) + `{"x":"` + label + `"}`, false},
		{"second-empty-object", string(valid) + "{}", false},
		{"8193", string(valid) + pad(8193-len(valid)), false},
		{"oversized-whitespace-junk", string(valid) + pad(8192) + "]", false},
		{"oversized-label", string(valid) + pad(8192) + label, false},
	}
	for _, tc := range cases {
		for _, chunked := range []bool{false, true} {
			for _, debug := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/chunked=%v/debug=%v", tc.name, chunked, debug), func(t *testing.T) {
					srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if !chunked {
							w.Header().Set("Content-Length", fmt.Sprint(len(tc.body)))
						}
						w.WriteHeader(http.StatusCreated)
						_, _ = io.WriteString(w, tc.body[:len(valid)])
						if f, ok := w.(http.Flusher); ok && chunked {
							f.Flush()
						}
						_, _ = io.WriteString(w, tc.body[len(valid):])
					}))
					defer srv.Close()
					args := []string{"input-link", "sample", "--ttl", "1h"}
					if debug {
						args = append(args, "--debug")
					}
					var out, errout bytes.Buffer
					code := run(args, nil, &out, &errout, inputLinkEnv(srv.URL))
					if tc.ok {
						if code != 0 {
							t.Fatalf("valid response refused: exit=%d", code)
						}
						requireInputLinkOutput(t, out.String(), "test-request")
						return
					}
					if code == 0 || out.Len() != 0 {
						t.Fatalf("malformed response accepted: exit=%d stdout=%d bytes", code, out.Len())
					}
					if probe.In(out.String()) || probe.In(errout.String()) || strings.Contains(errout.String(), label) {
						t.Fatal("synthetic label reached output")
					}
					if errout.String() != "keep: invalid input-link response\n" {
						t.Fatal("stderr is not the static error")
					}
				})
			}
		}
	}
}
