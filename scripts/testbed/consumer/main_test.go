package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// A redirect must neither carry the credential to another origin nor turn into
// a successful check: the status of the first answer is what verify reports.
func TestVerifyDoesNotFollowRedirects(t *testing.T) {
	const credential = "synthetic-credential-for-the-redirect-test"
	var seenAtOther atomic.Int32
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAtOther.Add(1)
		if r.Header.Get("X-Agent-Key") != "" {
			leaked.Store(true)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer front.Close()

	status, err := verify(front.URL, credential)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if status == http.StatusOK {
		t.Fatalf("a redirect to another origin was accepted as a successful check (status %d)", status)
	}
	if status != http.StatusFound {
		t.Fatalf("status = %d, want the redirect's own status %d", status, http.StatusFound)
	}
	if seenAtOther.Load() != 0 || leaked.Load() {
		t.Fatalf("the redirect target was contacted (%d requests), key forwarded: %v", seenAtOther.Load(), leaked.Load())
	}
}

// Positive control: a direct answer still passes through with its own status.
func TestVerifyReportsTheDirectStatus(t *testing.T) {
	for _, want := range []int{http.StatusOK, http.StatusUnauthorized} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Agent-Key") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(want)
		}))
		got, err := verify(srv.URL, "synthetic-credential")
		srv.Close()
		if err != nil || got != want {
			t.Fatalf("verify = (%d, %v), want (%d, nil)", got, err, want)
		}
	}
}

// A systemd credential is read from the unit's credentials directory under its
// name; no directory, a name that is not one path element or a missing file is
// no credential.
func TestReadCredential(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "creds")
	const want = "synthetic-credential-0123456789abcdef"
	// Every refused name below has a readable file behind it, so a refusal
	// can only come from the name and directory checks, not from a missing file.
	long := strings.Repeat("a", 129)
	for _, f := range []string{"creds/api_token", "creds/sub/api_token", "outside", "creds/.hidden", "creds/" + long, "creds/" + long[:128]} {
		p := filepath.Join(root, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(want+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	for _, name := range []string{"api_token", long[:128]} {
		if got, err := read("credential", name, ""); err != nil || got != want {
			t.Fatalf("read credential %d bytes: err=%v, match=%v", len(name), err, got == want)
		}
	}
	for _, name := range []string{"", "../outside", "sub/api_token", ".hidden", long, "other"} {
		if got, err := read("credential", name, ""); err == nil || got != "" {
			t.Fatalf("name %q: want an error and nothing, got err=%v len=%d", name, err, len(got))
		}
	}
	// No credentials directory: a file of that name in the working directory
	// must not be read instead.
	t.Chdir(dir)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if got, err := read("credential", "api_token", ""); err == nil || got != "" {
		t.Fatalf("no credentials directory: want an error and nothing, got err=%v len=%d", err, len(got))
	}
}
