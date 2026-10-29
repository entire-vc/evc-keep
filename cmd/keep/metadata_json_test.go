package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/entire-vc/evc-keep/internal/intake"
	"github.com/entire-vc/evc-keep/internal/testutil/canary"
)

func TestCLI_MetadataControlsNeverReachTerminal(t *testing.T) {
	c := canary.New()
	hostile := c.Value(0) + "\x1b[2J\x7f\u0085\u009b\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f\u061c\u2028\u2029"
	if !hasTerminalControl(hostile) || !c.In(hostile) {
		t.Fatal("detector positive control failed")
	}
	want := secret{ID: "test-secret", Name: hostile, Description: hostile, Class: hostile, Type: hostile, Scope: "org:test"}
	want.Store.Name = hostile
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/secrets") {
			_ = json.NewEncoder(w).Encode([]secret{want})
		} else {
			_ = json.NewEncoder(w).Encode(want)
		}
	}))
	defer srv.Close()
	e := &testEnv{t: t}
	for _, command := range []string{"list", "meta"} {
		for _, jsonOut := range []bool{false, true} {
			args := []string{command, "--scope-level", "org", "--scope-id", "test"}
			if command == "meta" {
				args = []string{command, hostile, "--scope-level", "org", "--scope-id", "test"}
			}
			if jsonOut {
				args = append(args, "--json")
			}
			res := e.runKeepAt(srv.URL, []string{"KEEP_TOKEN=test-credential"}, args...)
			if res.exitCode != 0 || !c.In(res.stdout) || res.stderr != "" {
				t.Fatal("metadata CLI probe failed to reach output")
			}
			if hasTerminalControl(strings.ReplaceAll(res.stdout, "\t", "")) {
				t.Fatal("raw metadata control reached terminal")
			}
			if jsonOut {
				var got secret
				if command == "list" {
					var rows []secret
					if json.Unmarshal([]byte(res.stdout), &rows) != nil || len(rows) != 1 {
						t.Fatal("list JSON invalid")
					}
					got = rows[0]
				} else if json.Unmarshal([]byte(res.stdout), &got) != nil {
					t.Fatal("meta JSON invalid")
				}
				if got.Name != hostile || got.Description != hostile || got.Store.Name != hostile {
					t.Fatal("JSON escaping changed metadata")
				}
			}
		}
	}
}

func TestJSONValueEscapesControlsAndPreservesUnicode(t *testing.T) {
	for _, value := range []string{"safe café 界 😀", "\x00\x1b\x7f\u0085\u009b\u202e\u2066\u200e\u061c\u2028\u2029\U000e0001", "\\u009b literal"} {
		var buf bytes.Buffer
		if writeJSONValue(&buf, value) != nil {
			t.Fatal("JSON write failed")
		}
		if hasTerminalControl(buf.String()) {
			t.Fatal("JSON writer emitted raw control")
		}
		var got string
		if json.Unmarshal(buf.Bytes(), &got) != nil || got != value {
			t.Fatal("JSON writer changed value")
		}
	}
}

func TestInputLinkJSONEscapesControls(t *testing.T) {
	c := canary.New()
	hostile := c.Value(0) + "\u009b\u202e\u2066\u200e\u061c"
	link := intake.Issued{URL: "https://keep.example.invalid/input/" + hostile, RequestID: hostile, ExpiresAt: time.Now().Add(time.Hour)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(link)
	}))
	defer srv.Close()
	e := &testEnv{t: t}
	res := e.runKeepAt(srv.URL, []string{"KEEP_TOKEN=test-credential"}, "input-link", "sample")
	if res.exitCode != 0 || !c.In(res.stdout) || res.stderr != "" {
		t.Fatal("input-link output probe failed")
	}
	if !hasTerminalControl(hostile) || hasTerminalControl(res.stdout) {
		t.Fatal("input-link emitted raw control")
	}
	var got intake.Issued
	if json.Unmarshal([]byte(res.stdout), &got) != nil || got.URL != link.URL || got.RequestID != link.RequestID {
		t.Fatal("input-link JSON changed the capability")
	}
}
