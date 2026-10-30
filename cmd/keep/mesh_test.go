package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/entire-vc/evc-keep/internal/testutil/canary"
	"github.com/google/uuid"
)

// meshStub stands in for Keep Server's removal route. It answers with the
// closed fields plus whatever extra the test plants, and counts the calls.
type meshStub struct {
	org, ws, token string
	calls          atomic.Int64
	srv            *httptest.Server

	mu     sync.Mutex // the handler runs on the server's goroutines
	extra  map[string]any
	status int
}

// answer sets what the stub answers from now on.
func (s *meshStub) answer(status int, extra map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.extra = status, extra
}

func newMeshStub(t *testing.T, token string) *meshStub {
	t.Helper()
	s := &meshStub{org: uuid.NewString(), ws: uuid.NewString(), token: token, status: http.StatusOK}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		if r.Method != http.MethodDelete || r.URL.Path != "/orgs/"+s.org+"/mesh/installations/"+s.ws ||
			r.Header.Get("Authorization") != "Bearer "+s.token {
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write([]byte(`{"error_class":"invalid_argument","message":"unexpected request","request_id":"req-stub"}`))
			return
		}
		s.mu.Lock()
		status, extra := s.status, s.extra
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status != http.StatusOK {
			_, _ = w.Write([]byte(`{"error_class":"not_found","message":"not found","request_id":"req-404"}`))
			return
		}
		body := map[string]any{"workspace_id": s.ws, "erased": 4, "request_id": "req-1"}
		for k, v := range extra {
			body[k] = v
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// execKeep runs the built binary against the stub with a hermetic
// environment and the given stdin.
func (s *meshStub) execKeep(t *testing.T, stdin string, args ...string) runResult {
	t.Helper()
	cmd := exec.Command(keepBinPath, args...) //nolint:gosec // G204: keepBinPath is the binary TestMain just built
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "KEEP_SERVER=" + s.srv.URL, "KEEP_ORG=" + s.org, "KEEP_TOKEN=" + s.token}
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run keep (%d args): %v", len(args), err)
	}
	return runResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: code}
}

// Leak test (written before the command): neither the bearer token nor
// anything the server sends beyond the closed fields reaches stdout or
// stderr, in table, JSON and --debug output alike.
func TestCLI_MeshUninstall_NeverLeaks(t *testing.T) {
	c := canary.New()
	if !c.In("x"+c.Value(1)) || !c.In(strings.ToUpper(c.Value(2))) {
		t.Fatal("canary detector is blind; the test proves nothing")
	}
	s := newMeshStub(t, c.Value(1))
	s.answer(http.StatusOK, map[string]any{"extension_token": c.Value(2), "value": c.Value(3), "fingerprint": "kfp1:k1:abcdefghij"})
	var outs []string
	for _, args := range [][]string{
		{"mesh", "uninstall", s.ws, "--yes"},
		{"mesh", "uninstall", s.ws, "--yes", "--json"},
		{"mesh", "uninstall", s.ws, "--yes", "--debug"},
	} {
		r := s.execKeep(t, "", args...)
		if r.exitCode != 0 || !strings.Contains(r.stdout, "4") || !strings.Contains(r.stdout, s.ws) {
			t.Fatalf("%v: exit %d, %d bytes of stdout", args[3:], r.exitCode, len(r.stdout))
		}
		outs = append(outs, r.stdout, r.stderr)
	}
	for i, out := range outs {
		if c.In(out) {
			t.Fatalf("output #%d (%d bytes) carries a canary", i, len(out))
		}
		if strings.Contains(out, "kfp1:") {
			t.Fatalf("output #%d carries a fingerprint the answer must not have", i)
		}
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(outs[2]), &res); err != nil {
		t.Fatalf("--json output is not JSON (%d bytes)", len(outs[2]))
	}
	if len(res) != 3 || res["workspace_id"] != s.ws || res["erased"] != float64(4) || res["request_id"] != "req-1" {
		t.Fatalf("--json output is not the closed shape: %d fields", len(res))
	}
}

// Without --yes the command asks, and anything but yes sends nothing.
func TestCLI_MeshUninstall_AsksFirst(t *testing.T) {
	s := newMeshStub(t, "tok-ask")
	for _, answer := range []string{"", "n\n", "no\n", "yess\n", s.ws + "\n"} {
		r := s.execKeep(t, answer, "mesh", "uninstall", s.ws)
		if r.exitCode != 1 || !strings.Contains(r.stderr, "[y/N]") || !strings.Contains(r.stderr, "nothing was removed") {
			t.Fatalf("answer %q: exit %d, stderr %q", answer, r.exitCode, r.stderr)
		}
	}
	if n := s.calls.Load(); n != 0 {
		t.Fatalf("an unconfirmed removal reached the server %d times", n)
	}
	r := s.execKeep(t, "y\n", "mesh", "uninstall", s.ws)
	if r.exitCode != 0 || s.calls.Load() != 1 {
		t.Fatalf("confirmed removal: exit %d, calls %d, stderr %q", r.exitCode, s.calls.Load(), r.stderr)
	}
}

// A workspace id that is not a UUID is refused before any call and never
// echoed; a server refusal prints its class and exits 1.
func TestCLI_MeshUninstall_Refusals(t *testing.T) {
	c := canary.New()
	s := newMeshStub(t, "tok-refuse")
	for _, args := range [][]string{
		{"mesh", "uninstall", c.Value(1), "--yes"},
		{"mesh", "uninstall"},
		{"mesh", "remove", s.ws},
		{"mesh", "uninstall", s.ws, "--yes", "extra"},
	} {
		r := s.execKeep(t, "", args...)
		if r.exitCode != 2 || c.In(r.stdout+r.stderr) {
			t.Fatalf("%d args: exit %d, want 2 and no echo", len(args), r.exitCode)
		}
	}
	if n := s.calls.Load(); n != 0 {
		t.Fatalf("a refused command reached the server %d times", n)
	}
	s.answer(http.StatusNotFound, nil)
	r := s.execKeep(t, "", "mesh", "uninstall", s.ws, "--yes")
	if r.exitCode != 1 || !strings.Contains(r.stderr, "not_found") || r.stdout != "" {
		t.Fatalf("server 404: exit %d, stderr %q", r.exitCode, r.stderr)
	}
}
