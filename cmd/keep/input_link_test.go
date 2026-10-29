package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
